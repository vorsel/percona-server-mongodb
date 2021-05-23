(function() {
"use strict";

load("jstests/sharding/libs/find_chunks_util.js");

let st = new ShardingTest({shards: 2});

assert.commandWorked(st.s.adminCommand({enableSharding: 'test'}));
st.ensurePrimaryShard('test', st.shard0.shardName);
assert.commandWorked(
    st.s.adminCommand({addShardToZone: st.shard1.shardName, zone: 'finalDestination'}));

////////////////////////////////////////////////////////////////////////////
// Ranged shard key
assert.commandWorked(st.s.adminCommand({shardCollection: 'test.range', key: {x: 1}}));
assert.commandWorked(st.s.adminCommand({split: 'test.range', middle: {x: 0}}));

let chunkColl = st.s.getDB('config').chunks;

let testRangeColl = st.s.getDB("config").collections.findOne({_id: 'test.range'});
if (testRangeColl.timestamp) {
    assert.commandWorked(
        chunkColl.update({uuid: testRangeColl.uuid, min: {x: 0}}, {$set: {jumbo: true}}));
} else {
    assert.commandWorked(chunkColl.update({ns: 'test.range', min: {x: 0}}, {$set: {jumbo: true}}));
}

let jumboChunk = findChunksUtil.findOneChunkByNs(st.s.getDB('config'), 'test.range', {min: {x: 0}});
assert(jumboChunk.jumbo, tojson(jumboChunk));
let jumboMajorVersionBefore = jumboChunk.lastmod.getTime();

// Target non-jumbo chunk should not affect real jumbo chunk.
assert.commandWorked(st.s.adminCommand({clearJumboFlag: 'test.range', find: {x: -1}}));
jumboChunk = findChunksUtil.findOneChunkByNs(st.s.getDB('config'), 'test.range', {min: {x: 0}});
assert(jumboChunk.jumbo, tojson(jumboChunk));
assert.eq(jumboMajorVersionBefore, jumboChunk.lastmod.getTime());

// Target real jumbo chunk should bump version.
assert.commandWorked(st.s.adminCommand({clearJumboFlag: 'test.range', find: {x: 1}}));
jumboChunk = findChunksUtil.findOneChunkByNs(st.s.getDB('config'), 'test.range', {min: {x: 0}});
assert(!jumboChunk.jumbo, tojson(jumboChunk));
assert.lt(jumboMajorVersionBefore, jumboChunk.lastmod.getTime());

////////////////////////////////////////////////////////////////////////////
// Hashed shard key
assert.commandWorked(
    st.s.adminCommand({shardCollection: 'test.hashed', key: {x: 'hashed'}, numInitialChunks: 2}));

let testHashedColl = st.s.getDB("config").collections.findOne({_id: 'test.hashed'});
if (testHashedColl.timestamp) {
    assert.commandWorked(
        chunkColl.update({uuid: testHashedColl.uuid, min: {x: 0}}, {$set: {jumbo: true}}));
} else {
    assert.commandWorked(chunkColl.update({ns: 'test.hashed', min: {x: 0}}, {$set: {jumbo: true}}));
}
jumboChunk = findChunksUtil.findOneChunkByNs(st.s.getDB("config"), 'test.hashed', {min: {x: 0}});
assert(jumboChunk.jumbo, tojson(jumboChunk));
jumboMajorVersionBefore = jumboChunk.lastmod.getTime();

// Target non-jumbo chunk should not affect real jumbo chunk.
let unrelatedChunk =
    findChunksUtil.findOneChunkByNs(st.s.getDB("config"), 'test.hashed', {min: {x: MinKey}});
assert.commandWorked(st.s.adminCommand(
    {clearJumboFlag: 'test.hashed', bounds: [unrelatedChunk.min, unrelatedChunk.max]}));
jumboChunk = findChunksUtil.findOneChunkByNs(st.s.getDB("config"), 'test.hashed', {min: {x: 0}});
assert(jumboChunk.jumbo, tojson(jumboChunk));
assert.eq(jumboMajorVersionBefore, jumboChunk.lastmod.getTime());

// Target real jumbo chunk should bump version.
assert.commandWorked(
    st.s.adminCommand({clearJumboFlag: 'test.hashed', bounds: [jumboChunk.min, jumboChunk.max]}));
jumboChunk = findChunksUtil.findOneChunkByNs(st.s.getDB("config"), 'test.hashed', {min: {x: 0}});
assert(!jumboChunk.jumbo, tojson(jumboChunk));
assert.lt(jumboMajorVersionBefore, jumboChunk.lastmod.getTime());

////////////////////////////////////////////////////////////////////////////
// Balancer with jumbo chunks behavior
// Forces a jumbo chunk to be on a wrong zone but balancer shouldn't be able to move it until
// jumbo flag is cleared.

st.stopBalancer();

if (testRangeColl.timestamp) {
    assert.commandWorked(
        chunkColl.update({uuid: testRangeColl.uuid, min: {x: 0}}, {$set: {jumbo: true}}));
} else {
    assert.commandWorked(chunkColl.update({ns: 'test.range', min: {x: 0}}, {$set: {jumbo: true}}));
}
assert.commandWorked(st.s.adminCommand(
    {updateZoneKeyRange: 'test.range', min: {x: 0}, max: {x: MaxKey}, zone: 'finalDestination'}));

let chunk = findChunksUtil.findOneChunkByNs(st.s.getDB("config"), 'test.range', {min: {x: 0}});
assert(chunk.jumbo, tojson(chunk));
assert.eq(st.shard0.shardName, chunk.shard);

st._configServers.forEach((conn) => {
    conn.adminCommand({
        configureFailPoint: 'overrideBalanceRoundInterval',
        mode: 'alwaysOn',
        data: {intervalMs: 200}
    });
});

let waitForBalancerToRun = function() {
    let lastRoundNumber =
        assert.commandWorked(st.s.adminCommand({balancerStatus: 1})).numBalancerRounds;
    st.startBalancer();

    assert.soon(function() {
        let res = assert.commandWorked(st.s.adminCommand({balancerStatus: 1}));
        return res.mode == "full" && res.numBalancerRounds - lastRoundNumber > 1;
    });

    st.stopBalancer();
};

waitForBalancerToRun();

chunk = findChunksUtil.findOneChunkByNs(st.s.getDB("config"), 'test.range', {min: {x: 0}});
assert.eq(st.shard0.shardName, chunk.shard);

assert.commandWorked(st.s.adminCommand({clearJumboFlag: 'test.range', find: {x: 0}}));

waitForBalancerToRun();

chunk = findChunksUtil.findOneChunkByNs(st.s.getDB("config"), 'test.range', {min: {x: 0}});
assert.eq(st.shard1.shardName, chunk.shard);

st.stop();
})();
