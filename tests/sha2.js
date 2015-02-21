// ----------------------------------------------------------------------------------------------------------------------------------------
// Unit test (Nodeunit) for SHA2 library. Test using test vectors from http://www.di-mgt.com.au/sha_testvectors.html.
// ----------------------------------------------------------------------------------------------------------------------------------------
// Author: Mark van den Brink (mark@askaround.nl)
// ----------------------------------------------------------------------------------------------------------------------------------------

var SHA2 = require('../compiled/sha2');

var sTest1 = "abc";
var sTest2 = "";
var sTest3 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
var sTest4 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
var sTest5 = "";
var sTest6 = "";
var nCount = 0;

while (nCount < 1000000) {
	sTest5 += "a";

	nCount++;
}

nCount = 0;

// Uses 64Mb of test data instead of the multiplier of 16,777,216 which results in 1Gb data.
while (nCount < 1048576) {
	sTest6 += "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";

	nCount++;
}

exports['SHA2.SHA2_224'] = function (pTest) {
    pTest.deepEqual(SHA2.SHA2_224(sTest1), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    pTest.deepEqual(SHA2.SHA2_224(sTest2), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    pTest.deepEqual(SHA2.SHA2_224(sTest3), "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
    pTest.deepEqual(SHA2.SHA2_224(sTest4), "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3");
    pTest.deepEqual(SHA2.SHA2_224(sTest5), "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67");
    pTest.deepEqual(SHA2.SHA2_224(sTest6), "41ed6f6ec6f642d4c9d9e5933f664b30120f5c0da8e90b74c7745612");
    pTest.done();
};

exports['SHA2.SHA2_256'] = function (pTest) {
    pTest.deepEqual(SHA2.SHA2_256(sTest1), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    pTest.deepEqual(SHA2.SHA2_256(sTest2), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    pTest.deepEqual(SHA2.SHA2_256(sTest3), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    pTest.deepEqual(SHA2.SHA2_256(sTest4), "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    pTest.deepEqual(SHA2.SHA2_256(sTest5), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    pTest.deepEqual(SHA2.SHA2_256(sTest6), "8716fbf9a5f8c4562b48528e2d3085b64c56b5d1169ccf3295ad03e805580676");
    pTest.done();
};

exports['SHA2.SHA2_384'] = function (pTest) {
    pTest.deepEqual(SHA2.SHA2_384(sTest1), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    pTest.deepEqual(SHA2.SHA2_384(sTest2), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    pTest.deepEqual(SHA2.SHA2_384(sTest3), "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");
    pTest.deepEqual(SHA2.SHA2_384(sTest4), "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
    pTest.deepEqual(SHA2.SHA2_384(sTest5), "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985");
    pTest.deepEqual(SHA2.SHA2_384(sTest6), "0de1d68a8dd5c8a50ea1cf28bccadcb5f14fc13b113033d45e4a558fbfb8ed7fc8dcab12ab8ba1d2be9516eb17e9dd03");
    pTest.done();
};

exports['SHA2.SHA2_512'] = function (pTest) {
    pTest.deepEqual(SHA2.SHA2_512(sTest1), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    pTest.deepEqual(SHA2.SHA2_512(sTest2), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    pTest.deepEqual(SHA2.SHA2_512(sTest3), "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
    pTest.deepEqual(SHA2.SHA2_512(sTest4), "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    pTest.deepEqual(SHA2.SHA2_512(sTest5), "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
    pTest.deepEqual(SHA2.SHA2_512(sTest6), "421b072b4fda96eb569ae55b8a9a5b4b5073a623649bd409dbb999e527372994b3a1a91f53c719837868c7fe11bba67640143255a3fbc5c895d2119274b0caff");
    pTest.done();
};

exports['SHA2.SHA2_512_224'] = function (pTest) {
    pTest.deepEqual(SHA2.SHA2_512_224(sTest1), "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
    pTest.deepEqual(SHA2.SHA2_512_224(sTest2), "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
    pTest.deepEqual(SHA2.SHA2_512_224(sTest3), "e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174");
    pTest.deepEqual(SHA2.SHA2_512_224(sTest4), "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9");
    pTest.deepEqual(SHA2.SHA2_512_224(sTest5), "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287");
    pTest.deepEqual(SHA2.SHA2_512_224(sTest6), "43b37719ba020a806b3f5af16c7dbdd8cb0728c96c0e56560fde96ee");
    pTest.done();
};

exports['SHA2.SHA2_512_256'] = function (pTest) {
    pTest.deepEqual(SHA2.SHA2_512_256(sTest1), "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
    pTest.deepEqual(SHA2.SHA2_512_256(sTest2), "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
    pTest.deepEqual(SHA2.SHA2_512_256(sTest3), "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461");
    pTest.deepEqual(SHA2.SHA2_512_256(sTest4), "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a");
    pTest.deepEqual(SHA2.SHA2_512_256(sTest5), "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21");
    pTest.deepEqual(SHA2.SHA2_512_256(sTest6), "e1c36669964a7adbaca1fe6192cfa71fa5480427ba11397b97303aef8cee7328");
    pTest.done();
};