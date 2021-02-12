#!/usr/bin/env python3
"""
Resmoke Test Suite Generator.

Analyze the evergreen history for tests run under the given task and create new evergreen tasks
to attempt to keep the task runtime under a specified amount.
"""

import datetime
from datetime import timedelta
import logging
import math
import os
import re
import sys
from collections import defaultdict
from distutils.util import strtobool  # pylint: disable=no-name-in-module
from typing import Set

import click
import requests
import structlog
import yaml

from evergreen.api import RetryingEvergreenApi
from pydantic import BaseModel
from shrub.config import Configuration
from shrub.command import CommandDefinition
from shrub.operations import CmdTimeoutUpdate
from shrub.task import TaskDependency
from shrub.variant import DisplayTaskDefinition
from shrub.variant import TaskSpec

# Get relative imports to work when the package is not installed on the PYTHONPATH.
if __name__ == "__main__" and __package__ is None:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import buildscripts.resmokelib.suitesconfig as suitesconfig  # pylint: disable=wrong-import-position
import buildscripts.util.read_config as read_config  # pylint: disable=wrong-import-position
import buildscripts.util.taskname as taskname  # pylint: disable=wrong-import-position
import buildscripts.util.testname as testname  # pylint: disable=wrong-import-position
from buildscripts.util.fileops import read_yaml_file  # pylint: disable=wrong-import-position

LOGGER = structlog.getLogger(__name__)

TEST_SUITE_DIR = os.path.join("buildscripts", "resmokeconfig", "suites")
CONFIG_DIR = "generated_resmoke_config"
AVG_SETUP_TIME = int(timedelta(minutes=5).total_seconds())
EVG_CONFIG_FILE = "./.evergreen.yml"
GENERATE_CONFIG_FILE = "etc/generate_subtasks_config.yml"
MIN_TIMEOUT_SECONDS = int(timedelta(minutes=5).total_seconds())
LOOKBACK_DURATION_DAYS = 14
GEN_SUFFIX = "_gen"

HEADER_TEMPLATE = """# DO NOT EDIT THIS FILE. All manual edits will be lost.
# This file was generated by {file} from
# {suite_file}.
"""

NO_LARGE_DISTRO_ERR = """
***************************************************************************************
It appears we are trying to generate a task marked as requiring a large distro, but the
build variant has not specified a large build variant. In order to resolve this error,
you need to:

(1) add a "large_distro_name" expansion to this build variant ("{build_variant}").

 -- or --
 
(2) add this build variant ("{build_variant}") to the "build_variant_large_distro_exception"
list in the "etc/generate_subtasks_config.yml" file.
***************************************************************************************
"""

REQUIRED_CONFIG_KEYS = {
    "build_variant",
    "fallback_num_sub_suites",
    "project",
    "task_id",
    "task_name",
}

DEFAULT_CONFIG_VALUES = {
    "max_tests_per_suite": 100,
    "resmoke_args": "",
    "resmoke_repeat_suites": 1,
    "run_multiple_jobs": "true",
    "target_resmoke_time": 60,
    "use_default_timeouts": False,
    "use_large_distro": False,
}

CONFIG_FORMAT_FN = {
    "fallback_num_sub_suites": int,
    "max_sub_suites": int,
    "max_tests_per_suite": int,
    "target_resmoke_time": int,
}


class GenerationConfiguration(BaseModel):
    """Configuration for generating sub-tasks."""

    build_variant_large_distro_exceptions: Set[str]

    @classmethod
    def from_yaml_file(cls, path: str) -> "GenerationConfiguration":
        """Read the generation configuration from the given file."""
        return cls(**read_yaml_file(path))

    @classmethod
    def default_config(cls) -> "GenerationConfiguration":
        """Create a default configuration."""
        return cls(build_variant_large_distro_exceptions=set())


class ConfigOptions(object):
    """Retrieve configuration from a config file."""

    def __init__(self, config, required_keys=None, defaults=None, formats=None):
        """
        Create an instance of ConfigOptions.

        :param config: Dictionary of configuration to use.
        :param required_keys: Set of keys required by this config.
        :param defaults: Dict of default values for keys.
        :param formats: Dict with functions to format values before returning.
        """
        self.config = config
        self.required_keys = required_keys if required_keys else set()
        self.default_values = defaults if defaults else {}
        self.formats = formats if formats else {}

    @classmethod
    def from_file(cls, filepath, required_keys, defaults, formats):
        """
        Create an instance of ConfigOptions based on the given config file.

        :param filepath: Path to file containing configuration.
        :param required_keys: Set of keys required by this config.
        :param defaults: Dict of default values for keys.
        :param formats: Dict with functions to format values before returning.
        :return: Instance of ConfigOptions.
        """
        return cls(read_config.read_config_file(filepath), required_keys, defaults, formats)

    @property
    def depends_on(self):
        """List of dependencies specified."""
        return split_if_exists(self._lookup(self.config, "depends_on"))

    @property
    def is_patch(self):
        """Is this running in a patch build."""
        patch = self.config.get("is_patch")
        if patch:
            return strtobool(patch)
        return None

    @property
    def repeat_suites(self):
        """How many times should the suite be repeated."""
        return int(self.resmoke_repeat_suites)

    @property
    def suite(self):
        """Return test suite is being run."""
        return self.config.get("suite", self.task)

    @property
    def task(self):
        """Return task being run."""
        return remove_gen_suffix(self.task_name)

    @property
    def variant(self):
        """Return build variant is being run on."""
        return self.build_variant

    def _lookup(self, config, item):
        if item not in config:
            if item in self.required_keys:
                raise KeyError(f"{item} must be specified in configuration.")
            return self.default_values.get(item, None)

        if item in self.formats and item in config:
            return self.formats[item](config[item])

        return config.get(item, None)

    def __getattr__(self, item):
        """Determine the value of the given attribute."""
        return self._lookup(self.config, item)

    def __repr__(self):
        """Provide a string representation of this object for debugging."""
        required_values = [f"{key}: {self.config[key]}" for key in REQUIRED_CONFIG_KEYS]
        return f"ConfigOptions({', '.join(required_values)})"


def enable_logging(verbose):
    """Enable verbose logging for execution."""

    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="[%(asctime)s - %(name)s - %(levelname)s] %(message)s",
        level=level,
        stream=sys.stdout,
    )
    structlog.configure(logger_factory=structlog.stdlib.LoggerFactory())


def split_if_exists(str_to_split):
    """Split the given string on "," if it is not None."""
    if str_to_split:
        return str_to_split.split(",")
    return None


def remove_gen_suffix(task_name):
    """Remove '_gen' suffix from task_name."""
    if task_name.endswith(GEN_SUFFIX):
        return task_name[:-4]
    return task_name


def string_contains_any_of_args(string, args):
    """
    Return whether array contains any of a group of args.

    :param string: String being checked.
    :param args: Args being analyzed.
    :return: True if any args are found in the string.
    """
    return any(arg in string for arg in args)


def divide_remaining_tests_among_suites(remaining_tests_runtimes, suites):
    """Divide the list of tests given among the suites given."""
    suite_idx = 0
    for test_file, runtime in remaining_tests_runtimes:
        current_suite = suites[suite_idx]
        current_suite.add_test(test_file, runtime)
        suite_idx += 1
        if suite_idx >= len(suites):
            suite_idx = 0


def _new_suite_needed(current_suite, test_runtime, max_suite_runtime, max_tests_per_suite):
    """
    Check if a new suite should be created for the given suite.

    :param current_suite: Suite currently being added to.
    :param test_runtime: Runtime of test being added.
    :param max_suite_runtime: Max runtime of a single suite.
    :param max_tests_per_suite: Max number of tests in a suite.
    :return: True if a new test suite should be created.
    """
    if current_suite.get_runtime() + test_runtime > max_suite_runtime:
        # Will adding this test put us over the target runtime?
        return True

    if max_tests_per_suite and current_suite.get_test_count() + 1 > max_tests_per_suite:
        # Will adding this test put us over the max number of tests?
        return True

    return False


def divide_tests_into_suites(tests_runtimes, max_time_seconds, max_suites=None,
                             max_tests_per_suite=None):
    """
    Divide the given tests into suites.

    Each suite should be able to execute in less than the max time specified. If a single
    test has a runtime greater than `max_time_seconds`, it will be run in a suite on its own.

    If max_suites is reached before assigning all tests to a suite, the remaining tests will be
    divided up among the created suites.

    Note: If `max_suites` is hit, suites may have more tests than `max_tests_per_suite` and may have
    runtimes longer than `max_time_seconds`.

    :param tests_runtimes: List of tuples containing test names and test runtimes.
    :param max_time_seconds: Maximum runtime to add to a single bucket.
    :param max_suites: Maximum number of suites to create.
    :param max_tests_per_suite: Maximum number of tests to add to a single suite.
    :return: List of Suite objects representing grouping of tests.
    """
    suites = []
    current_suite = Suite()
    last_test_processed = len(tests_runtimes)
    LOGGER.debug("Determines suites for runtime", max_runtime_seconds=max_time_seconds,
                 max_suites=max_suites, max_tests_per_suite=max_tests_per_suite)
    for idx, (test_file, runtime) in enumerate(tests_runtimes):
        LOGGER.debug("Adding test", test=test_file, test_runtime=runtime)
        if _new_suite_needed(current_suite, runtime, max_time_seconds, max_tests_per_suite):
            LOGGER.debug("Finished suite", suite_runtime=current_suite.get_runtime(),
                         test_runtime=runtime, max_time=max_time_seconds)
            if current_suite.get_test_count() > 0:
                suites.append(current_suite)
                current_suite = Suite()
                if max_suites and len(suites) >= max_suites:
                    last_test_processed = idx
                    break

        current_suite.add_test(test_file, runtime)

    if current_suite.get_test_count() > 0:
        suites.append(current_suite)

    if max_suites and last_test_processed < len(tests_runtimes):
        # We must have hit the max suite limit, just randomly add the remaining tests to suites.
        divide_remaining_tests_among_suites(tests_runtimes[last_test_processed:], suites)

    return suites


def update_suite_config(suite_config, roots=None, excludes=None):
    """
    Update suite config based on the roots and excludes passed in.

    :param suite_config: suite_config to update.
    :param roots: new roots to run, or None if roots should not be updated.
    :param excludes: excludes to add, or None if excludes should not be include.
    :return: updated suite_config
    """
    if roots:
        suite_config["selector"]["roots"] = roots

    if excludes:
        # This must be a misc file, if the exclude_files section exists, extend it, otherwise,
        # create it.
        if "exclude_files" in suite_config["selector"] and \
                suite_config["selector"]["exclude_files"]:
            suite_config["selector"]["exclude_files"] += excludes
        else:
            suite_config["selector"]["exclude_files"] = excludes
    else:
        # if excludes was not specified this must not a misc file, so don"t exclude anything.
        if "exclude_files" in suite_config["selector"]:
            del suite_config["selector"]["exclude_files"]

    return suite_config


def generate_subsuite_file(source_suite_name, target_suite_name, roots=None, excludes=None):
    """
    Read and evaluate the yaml suite file.

    Override selector.roots and selector.excludes with the provided values. Write the results to
    target_suite_name.
    """
    source_file = os.path.join(TEST_SUITE_DIR, source_suite_name + ".yml")
    with open(source_file, "r") as fstream:
        suite_config = yaml.safe_load(fstream)

    with open(os.path.join(CONFIG_DIR, target_suite_name + ".yml"), "w") as out:
        out.write(HEADER_TEMPLATE.format(file=__file__, suite_file=source_file))
        suite_config = update_suite_config(suite_config, roots, excludes)
        out.write(yaml.dump(suite_config, default_flow_style=False, Dumper=yaml.SafeDumper))


def render_suite(suites, suite_name):
    """Render the given suites into yml files that can be used by resmoke.py."""
    for idx, suite in enumerate(suites):
        suite.name = taskname.name_generated_task(suite_name, idx, len(suites))
        generate_subsuite_file(suite_name, suite.name, roots=suite.tests)


def render_misc_suite(test_list, suite_name):
    """Render a misc suite to run any tests that might be added to the directory."""
    subsuite_name = "{0}_{1}".format(suite_name, "misc")
    generate_subsuite_file(suite_name, subsuite_name, excludes=test_list)


def prepare_directory_for_suite(directory):
    """Ensure that dir exists."""
    if not os.path.exists(directory):
        os.makedirs(directory)


def calculate_timeout(avg_runtime, scaling_factor):
    """
    Determine how long a runtime to set based on average runtime and a scaling factor.

    :param avg_runtime: Average runtime of previous runs.
    :param scaling_factor: scaling factor for timeout.
    :return: timeout to use (in seconds).
    """

    def round_to_minute(runtime):
        """Round the given seconds up to the nearest minute."""
        distance_to_min = 60 - (runtime % 60)
        return int(math.ceil(runtime + distance_to_min))

    return max(MIN_TIMEOUT_SECONDS, round_to_minute(avg_runtime)) * scaling_factor + AVG_SETUP_TIME


def should_tasks_be_generated(evg_api, task_id):
    """
    Determine if we should attempt to generate tasks.

    If an evergreen task that calls 'generate.tasks' is restarted, the 'generate.tasks' command
    will no-op. So, if we are in that state, we should avoid generating new configuration files
    that will just be confusing to the user (since that would not be used).

    :param evg_api: Evergreen API object.
    :param task_id: Id of the task being run.
    :return: Boolean of whether to generate tasks.
    """
    task = evg_api.task_by_id(task_id, fetch_all_executions=True)
    # If any previous execution was successful, do not generate more tasks.
    for i in range(task.execution):
        task_execution = task.get_execution(i)
        if task_execution.is_success():
            return False

    return True


class EvergreenConfigGenerator(object):
    """Generate evergreen configurations."""

    # pylint: disable=too-many-instance-attributes
    def __init__(self, suites, options, evg_api, generate_config=None):
        """Create new EvergreenConfigGenerator object."""
        self.suites = suites
        self.options = options
        self.gen_config = GenerationConfiguration.default_config()
        if generate_config:
            self.gen_config = generate_config
        self.evg_api = evg_api
        self.evg_config = Configuration()
        self.task_specs = []
        self.task_names = []
        self.build_tasks = None

    def _set_task_distro(self, task_spec):
        if self.options.use_large_distro:
            if self.options.large_distro_name:
                task_spec.distro(self.options.large_distro_name)
                return

            if self.options.variant not in self.gen_config.build_variant_large_distro_exceptions:
                print(NO_LARGE_DISTRO_ERR.format(build_variant=self.options.variant))
                raise ValueError("Invalid Evergreen Configuration")

    def _generate_resmoke_args(self, suite_file):
        resmoke_args = "--suite={0}.yml --originSuite={1} {2}".format(
            suite_file, self.options.suite, self.options.resmoke_args)
        if self.options.repeat_suites and not string_contains_any_of_args(
                resmoke_args, ["repeatSuites", "repeat"]):
            resmoke_args += " --repeatSuites={0} ".format(self.options.repeat_suites)

        return resmoke_args

    def _get_run_tests_vars(self, suite_file):
        variables = {
            "resmoke_args": self._generate_resmoke_args(suite_file),
            "run_multiple_jobs": self.options.run_multiple_jobs,
            "task": self.options.task,
        }

        if self.options.resmoke_jobs_max:
            variables["resmoke_jobs_max"] = self.options.resmoke_jobs_max

        if self.options.use_multiversion:
            variables["task_path_suffix"] = self.options.use_multiversion

        return variables

    def _add_timeout_command(self, commands, max_test_runtime, expected_suite_runtime):
        """
        Add an evergreen command to override the default timeouts to the list of commands.

        :param commands: List of commands to add timeout command to.
        :param max_test_runtime: Maximum runtime of any test in the sub-suite.
        :param expected_suite_runtime: Expected runtime of the entire sub-suite.
        """
        repeat_factor = self.options.repeat_suites
        if max_test_runtime or expected_suite_runtime:
            cmd_timeout = CmdTimeoutUpdate()
            if max_test_runtime:
                timeout = calculate_timeout(max_test_runtime, 3) * repeat_factor
                LOGGER.debug("Setting timeout", timeout=timeout, max_runtime=max_test_runtime,
                             factor=repeat_factor)
                cmd_timeout.timeout(timeout)
            if expected_suite_runtime:
                exec_timeout = calculate_timeout(expected_suite_runtime, 3) * repeat_factor
                LOGGER.debug("Setting exec_timeout", exec_timeout=exec_timeout,
                             suite_runtime=expected_suite_runtime, factor=repeat_factor)
                cmd_timeout.exec_timeout(exec_timeout)
            commands.append(cmd_timeout.validate().resolve())

    @staticmethod
    def _is_task_dependency(task, possible_dependency):
        return re.match("{0}_(\\d|misc)".format(task), possible_dependency)

    def _get_tasks_for_depends_on(self, dependent_task):
        return [
            str(task.display_name) for task in self.build_tasks
            if self._is_task_dependency(dependent_task, str(task.display_name))
        ]

    def _add_dependencies(self, task):
        task.dependency(TaskDependency("compile"))
        if not self.options.is_patch:
            # Don"t worry about task dependencies in patch builds, only mainline.
            if self.options.depends_on:
                for dep in self.options.depends_on:
                    depends_on_tasks = self._get_tasks_for_depends_on(dep)
                    for dependency in depends_on_tasks:
                        task.dependency(TaskDependency(dependency))

        return task

    def _generate_task(self, sub_suite_name, sub_task_name, max_test_runtime=None,
                       expected_suite_runtime=None):
        """Generate evergreen config for a resmoke task."""
        LOGGER.debug("Generating task", sub_suite=sub_suite_name)
        spec = TaskSpec(sub_task_name)
        self._set_task_distro(spec)
        self.task_specs.append(spec)

        self.task_names.append(sub_task_name)
        task = self.evg_config.task(sub_task_name)

        target_suite_file = os.path.join(CONFIG_DIR, sub_suite_name)
        run_tests_vars = self._get_run_tests_vars(target_suite_file)

        commands = []
        if not self.options.use_default_timeouts:
            self._add_timeout_command(commands, max_test_runtime, expected_suite_runtime)
        commands.append(CommandDefinition().function("do setup"))
        if self.options.use_multiversion:
            commands.append(CommandDefinition().function("do multiversion setup"))
        commands.append(CommandDefinition().function("run generated tests").vars(run_tests_vars))

        self._add_dependencies(task).commands(commands)

    def _generate_all_tasks(self):
        for idx, suite in enumerate(self.suites):
            sub_task_name = taskname.name_generated_task(self.options.task, idx, len(self.suites),
                                                         self.options.variant)
            max_runtime = None
            total_runtime = None
            if suite.should_overwrite_timeout():
                max_runtime = suite.max_runtime
                total_runtime = suite.get_runtime()
            self._generate_task(suite.name, sub_task_name, max_runtime, total_runtime)

        # Add the misc suite
        misc_suite_name = "{0}_misc".format(self.options.suite)
        self._generate_task(misc_suite_name, "{0}_misc_{1}".format(self.options.task,
                                                                   self.options.variant))

    def _generate_display_task(self):
        dt = DisplayTaskDefinition(self.options.task)\
            .execution_tasks(self.task_names) \
            .execution_task("{0}_gen".format(self.options.task))
        return dt

    def _generate_variant(self):
        self._generate_all_tasks()

        self.evg_config.variant(self.options.variant)\
            .tasks(self.task_specs)\
            .display_task(self._generate_display_task())

    def generate_config(self):
        """Generate evergreen configuration."""
        self.build_tasks = self.evg_api.tasks_by_build(self.options.build_id)
        self._generate_variant()
        return self.evg_config


def normalize_test_name(test_name):
    """Normalize test names that may have been run on windows or unix."""
    return test_name.replace("\\", "/")


class TestStats(object):
    """Represent the test statistics for the task that is being analyzed."""

    def __init__(self, evg_test_stats_results):
        """Initialize the TestStats with raw results from the Evergreen API."""
        # Mapping from test_file to {"num_run": X, "duration": Y} for tests
        self._runtime_by_test = defaultdict(dict)
        # Mapping from 'test_name:hook_name' to
        #       {'test_name': {hook_name': {"num_run": X, "duration": Y}}}
        self._hook_runtime_by_test = defaultdict(lambda: defaultdict(dict))

        for doc in evg_test_stats_results:
            self._add_stats(doc)

    def _add_stats(self, test_stats):
        """Add the statistics found in a document returned by the Evergreen test_stats/ endpoint."""
        test_file = testname.normalize_test_file(test_stats.test_file)
        duration = test_stats.avg_duration_pass
        num_run = test_stats.num_pass
        is_hook = testname.is_resmoke_hook(test_file)
        if is_hook:
            self._add_test_hook_stats(test_file, duration, num_run)
        else:
            self._add_test_stats(test_file, duration, num_run)

    def _add_test_stats(self, test_file, duration, num_run):
        """Add the statistics for a test."""
        runtime_info = self._runtime_by_test[test_file]
        self._add_runtime_info(runtime_info, duration, num_run)

    def _add_test_hook_stats(self, test_file, duration, num_run):
        """Add the statistics for a hook."""
        test_name, hook_name = testname.split_test_hook_name(test_file)
        runtime_info = self._hook_runtime_by_test[test_name][hook_name]
        self._add_runtime_info(runtime_info, duration, num_run)

    @staticmethod
    def _add_runtime_info(runtime_info, duration, num_run):
        if not runtime_info:
            runtime_info["duration"] = duration
            runtime_info["num_run"] = num_run
        else:
            runtime_info["duration"] = TestStats._average(
                runtime_info["duration"], runtime_info["num_run"], duration, num_run)
            runtime_info["num_run"] += num_run

    @staticmethod
    def _average(value_a, num_a, value_b, num_b):
        """Compute a weighted average of 2 values with associated numbers."""
        divisor = num_a + num_b
        if divisor == 0:
            return 0
        else:
            return float(value_a * num_a + value_b * num_b) / divisor

    def get_tests_runtimes(self):
        """Return the list of (test_file, runtime_in_secs) tuples ordered by decreasing runtime."""
        tests = []
        for test_file, runtime_info in list(self._runtime_by_test.items()):
            duration = runtime_info["duration"]
            test_name = testname.get_short_name_from_test_file(test_file)
            for _, hook_runtime_info in self._hook_runtime_by_test[test_name].items():
                duration += hook_runtime_info["duration"]
            tests.append((normalize_test_name(test_file), duration))
        return sorted(tests, key=lambda x: x[1], reverse=True)


class Suite(object):
    """A suite of tests that can be run by evergreen."""

    def __init__(self):
        """Initialize the object."""
        self.tests = []
        self.total_runtime = 0
        self.max_runtime = 0
        self.tests_with_runtime_info = 0

    def add_test(self, test_file, runtime):
        """Add the given test to this suite."""

        self.tests.append(test_file)
        self.total_runtime += runtime

        if runtime != 0:
            self.tests_with_runtime_info += 1

        if runtime > self.max_runtime:
            self.max_runtime = runtime

    def should_overwrite_timeout(self):
        """
        Whether the timeout for this suite should be overwritten.

        We should only overwrite the timeout if we have runtime info for all tests.
        """
        return len(self.tests) == self.tests_with_runtime_info

    def get_runtime(self):
        """Get the current average runtime of all the tests currently in this suite."""

        return self.total_runtime

    def get_test_count(self):
        """Get the number of tests currently in this suite."""

        return len(self.tests)


class GenerateSubSuites(object):
    """Orchestrate the execution of generate_resmoke_suites."""

    def __init__(self, evergreen_api, config_options, generate_config=None):
        """Initialize the object."""
        self.evergreen_api = evergreen_api
        self.config_options = config_options
        self.generate_options = GenerationConfiguration.default_config()
        if generate_config:
            self.generate_options = generate_config
        self.test_list = []

    def calculate_suites(self, start_date, end_date):
        """Divide tests into suites based on statistics for the provided period."""
        try:
            evg_stats = self.get_evg_stats(self.config_options.project, start_date, end_date,
                                           self.config_options.task, self.config_options.variant)
            if not evg_stats:
                # This is probably a new suite, since there is no test history, just use the
                # fallback values.
                return self.calculate_fallback_suites()
            target_execution_time_secs = self.config_options.target_resmoke_time * 60
            return self.calculate_suites_from_evg_stats(evg_stats, target_execution_time_secs)
        except requests.HTTPError as err:
            if err.response.status_code == requests.codes.SERVICE_UNAVAILABLE:
                # Evergreen may return a 503 when the service is degraded.
                # We fall back to splitting the tests into a fixed number of suites.
                LOGGER.warning("Received 503 from Evergreen, "
                               "dividing the tests evenly among suites")
                return self.calculate_fallback_suites()
            else:
                raise

    def get_evg_stats(self, project, start_date, end_date, task, variant):
        """Collect test execution statistics data from Evergreen."""
        # pylint: disable=too-many-arguments

        days = (end_date - start_date).days
        return self.evergreen_api.test_stats_by_project(
            project, after_date=start_date.strftime("%Y-%m-%d"),
            before_date=end_date.strftime("%Y-%m-%d"), tasks=[task], variants=[variant],
            group_by="test", group_num_days=days)

    def calculate_suites_from_evg_stats(self, data, execution_time_secs):
        """Divide tests into suites that can be run in less than the specified execution time."""
        test_stats = TestStats(data)
        tests_runtimes = self.filter_existing_tests(test_stats.get_tests_runtimes())
        if not tests_runtimes:
            return self.calculate_fallback_suites()
        self.test_list = [info[0] for info in tests_runtimes]
        return divide_tests_into_suites(tests_runtimes, execution_time_secs,
                                        self.config_options.max_sub_suites,
                                        self.config_options.max_tests_per_suite)

    def filter_existing_tests(self, tests_runtimes):
        """Filter out tests that do not exist in the filesystem."""
        all_tests = [normalize_test_name(test) for test in self.list_tests()]
        return [info for info in tests_runtimes if os.path.exists(info[0]) and info[0] in all_tests]

    def calculate_fallback_suites(self):
        """Divide tests into a fixed number of suites."""
        num_suites = self.config_options.fallback_num_sub_suites
        self.test_list = self.list_tests()
        suites = [Suite() for _ in range(num_suites)]
        for idx, test_file in enumerate(self.test_list):
            suites[idx % num_suites].add_test(test_file, 0)
        return suites

    def list_tests(self):
        """List the test files that are part of the suite being split."""
        return suitesconfig.get_suite(self.config_options.suite).tests

    def write_evergreen_configuration(self, suites, task):
        """Generate the evergreen configuration for the new suite and write it to disk."""
        evg_config_gen = EvergreenConfigGenerator(suites, self.config_options, self.evergreen_api,
                                                  self.generate_options)
        evg_config = evg_config_gen.generate_config()

        with open(os.path.join(CONFIG_DIR, task + ".json"), "w") as file_handle:
            file_handle.write(evg_config.to_json())

    def run(self):
        """Generate resmoke suites that run within a specified target execution time."""
        LOGGER.debug("config options", config_options=self.config_options)

        if not should_tasks_be_generated(self.evergreen_api, self.config_options.task_id):
            LOGGER.info("Not generating configuration due to previous successful generation.")
            return

        end_date = datetime.datetime.utcnow().replace(microsecond=0)
        start_date = end_date - datetime.timedelta(days=LOOKBACK_DURATION_DAYS)

        prepare_directory_for_suite(CONFIG_DIR)

        suites = self.calculate_suites(start_date, end_date)

        LOGGER.debug("Creating suites", num_suites=len(suites), task=self.config_options.task)

        render_suite(suites, self.config_options.suite)
        render_misc_suite(self.test_list, self.config_options.suite)

        self.write_evergreen_configuration(suites, self.config_options.task)


@click.command()
@click.option("--expansion-file", type=str, required=True,
              help="Location of expansions file generated by evergreen.")
@click.option("--evergreen-config", type=str, default=EVG_CONFIG_FILE,
              help="Location of evergreen configuration file.")
@click.option("--verbose", is_flag=True, default=False, help="Enable verbose logging.")
def main(expansion_file, evergreen_config, verbose):
    """
    Create a configuration for generate tasks to create sub suites for the specified resmoke suite.

    The `--expansion-file` should contain all the configuration needed to generate the tasks.
    \f
    :param expansion_file: Configuration file.
    :param evergreen_config: Evergreen configuration file.
    :param verbose: Use verbose logging.
    """
    enable_logging(verbose)
    evg_api = RetryingEvergreenApi.get_api(config_file=evergreen_config)
    generate_config = GenerationConfiguration.from_yaml_file(GENERATE_CONFIG_FILE)
    config_options = ConfigOptions.from_file(expansion_file, REQUIRED_CONFIG_KEYS,
                                             DEFAULT_CONFIG_VALUES, CONFIG_FORMAT_FN)

    GenerateSubSuites(evg_api, config_options, generate_config).run()


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
