/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.core;

import com.google.common.io.ByteStreams;

import org.bitcoinj.core.AbstractBlockChain.NewBlockType;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.script.ScriptOpCodes;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.Wallet.BalanceType;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;

import static org.junit.Assert.*;
import static org.bitcoinj.core.Utils.HEX;

public class BlockTest {
    public static final byte[] blockBytes;

    static {
        // Block 000000001f1afc05cb4403f5776c863afd4c71da4e4ea184e43e41b25d071b15 ; height of 1084745
        // One with lots of transactions in, so a good test of the merkle tree hashing.
        blockBytes = HEX.decode("03000000a0631263949e18857a5ce7afad030ee6a47500ce6ebe69d92087fe1100000000a9835e3aca32d1b0fe0fb764a063ca49f25d6b6adfb12aed4f7a2df05635e58f451f30571ba52d1c253ee5e00601000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2003498d1004451f305708f807250ebf2200000d2f7374726174756d506f6f6c2f000000000106891d3b000000001976a91448b925a28f91cd8931cfa3c72698026389b91df788ac000000000100000003a6c2234f0e6ca035d217e1c39f1b6daa2b1ee030727cdc8fee06cfe2ceb97d3d000000006b48304502210086a0de23ffc2bf1ba1a2d34520451ad37b0520d235f1e1f33a7c35c65352052002206942399ccb2a252a16fa00122f257bbb307eb19ce49ae57ff64089c9ef910095012103ffa158ec91d27968bce8bf66edb02f9619bb7e59534453374097a1d0f6265632feffffffdcac92187853af22c62524ffd3e6f9dedeb0207430cf49e5a0297edd222d8acb000000006a47304402207dc8620e9453661b15812dbe9b77248afd1ad6ba12f83fa1cfce8a634b6b51a8022018c8bac9e25fafc1317bca1a711b03a7af89ae369b7a7eab22e73617b8bdcbad01210393b59bbaaa664411a3e238c74de120ebd17b5c67362e7c7158e564950163b78afefffffff2c3d8a1a7a6710827da4323fceee9f50269c7b2f57903301c5fa91c94ebcadf000000006a47304402206ded40033447819ea4f3913cf9dac7f4869e3247b770eb4faac00b36b865052b022078775c785a4473beeb817f89c4aee5a38f028b7841df29e6bf58d29b5c7446770121020980a23f036eb82c56ff858a556d658f07cf829b7d9719a0eef24173462b45dbfeffffff02772ed791ff0100001976a9146bc46b196252194895661e67162606cd3e08fd6c88ac00a0724e180900001976a914548f78d693b08cbed5e889d4b7c7c4f806231fa388ac3d8d100001000000014b0a1f2aa74a626704c499b5796862e7415645bee6dcb8bacd1b815259d18b69010000006a47304402202d845f4e212ac76c6db0740e1d6ae976852d418fa9caf06dd6303ed87575dc7f02205a1fc14095ecab33bd74c6ec1c76ce60c4508edd0ed4207f5c2cabd583ad94ec01210247bbb055d9938b3d24025788d96a8358d36d6ce9cd096ce374cbe42be101f26efeffffff020088526a740000001976a914548f78d693b08cbed5e889d4b7c7c4f806231fa388ace03684431f0200001976a914022c176ad76bce0c16b02ecfc6efd5a6bb9e88b488ac3c8d1000010000000142f16ce072ee07c47212521e6de8caf2ce91f3388391c5b2df00313d93196321010000006b483045022100c221251acd05a0fb335a10131930a7a65c55a705f1939e804041a0bfc50bddd3022008f97c72b8542f16e626a9747556862e4c70be0e499275736c2e087f2b2373f401210296a461bbe90114f96a412d2c0a31086867b91dda3e567b34970a3358230f0932feffffff02e0ae31d9aa0100001976a91418a200110a6bc596361ec9978ea2ea607e4559bb88ac0010a5d4e80000001976a914548f78d693b08cbed5e889d4b7c7c4f806231fa388ac3d8d10000100000004cfc5c33f8e2a04a4fdfe7dbe1de8518fee9b4aaf7e31f0f1b66e22600adf4935010000006b483045022100d769beca8272649beaa04c69f7ccc745df5d14168586965d0f70351d9b9c5d9c02206dcd44703d2ec304594b8748ac45d1520471d962b75af911a3c40abb75984013012103a6c85920f55a9da129be1413b1e607f28b11a5d82b1b11aa70a4daccd23de26dfeffffff2ba54737233e4cc3521f514349fcee39923836eda6fc387525a153354a290a7f000000006b4830450221009c45a521c70e4fc7ef97690ad6a1f0dd425e27810ed98aa922dfb61ade117c530220433c0d0c2a615dec42b9be02b6fc67ca855f500f7c3cde0a79340bc725361615012103196d518dda1682129404111e69002d9c668ad30cc62d6e433303817a935011cffeffffff804434f19a2cc8963e49e010994574790c95d4ae5646e024c0eb15c552b45cde000000006a47304402205d65ab51d70d35deb1ce908284f72ca243a851064e8b5fe811436bbe5ed6a98802200fc2d9823d019b64b3ff62596fc2eb715a18ac1f3fc953a9b262781fd8ea73840121029d90fbfe425937abd8dff975fc302a87c90820969fc8d896c05e6380af11a67afeffffff2070b4f25ed40cf07e2e1475dabc2688a6489f224964fe4fcef001979cb8ed88010000006a47304402204691d85f5e9ae577131c80ecb83a54f03a1e0e2db810a8235c999c5a815a778502200ae162f0abe3d2bbda4dbb91fb81ba7a5863c373f4ccca5e8fc3f0eda8ae5612012102011fe3f6c6032c0edf978dca53a0e5bd54b4abd287552cb5477661944e8d8630feffffff0217ee001dc90000001976a914845d609b8a095ecc6004680b7e9129858245393588ac00a0724e180900001976a914548f78d693b08cbed5e889d4b7c7c4f806231fa388ac3d8d100001000000268b9de05d96b3a5124089fc777748fa38b473024a8ac036d68801f4391cd35471000000006b483045022100e1bb8e423957ffa2939a03146fa11363043776d77b22c3137c5734456693fc4502200c7ec261b4f0167f1b994532a930de79c203eb8db4432cc6efc958d28b393a6f0121034076d24b933d1e6bd126a086a09eb8f9a2584f3c4539a8477461a09808c970ebfeffffff32a0a017b9c763f3f821080e8bff5e43817dcf96e020ac3d6079e64ad4c31a47000000006b483045022100fd1d58be3f6af7abafd2c520a309123eb81d77593ad58e3612106e1f8d15a4a502207167e122b5890ddf7741f200559e834fd4097982da4708e9c1a72c9aaaf8f46901210293e7d98984928f8b4ae46b01a2129cd2bdf2b5ef35c85f5d42384ff6ebca05befeffffffbd9f335e9598054e62e5ae2743bf8294465472fdaac5c474be9018c30f74423a000000006a473044022100c5033637a5e9f6707aa8136b28eecfb61838a01fe7e4dcae8ba47ec3e47ec890021f0d366f601f1e4e458bdf4fda58f5643b7c88cb1cf4fb8ccc96943cde597d5a012103681d2e74f9d72fcf0f30ffda2124e60cbb75a77ba6bb01c8dbd698c67a4dd4bafeffffffe4fa585e17eed934d6bee1264b79e167da954970797bc70046d76c9d7847c46a010000006a47304402202a1b67cf0c632fa85bbc0831f0a572e73cfcf55b0ce799dd72d2e90a3dcfa0ec022053723c8060df2f2333c036c8e92f6f850955f21de8c07a0c0d70236e8175c5500121027d9c2c9536fbf43cbb965f0a2bf5984950acbae732919ad1fbc18af1a2bf0f46feffffff1a54f5b5744e0c75bc0e551b6b584222590ac546447709eda5e0af45510376d4010000006a47304402201e16a952beb29c9ef0cbc5b389abc163610b9e43d569fb6ae69f37d65ec7d4ff022021858163e06105e6ad5e7da0bfdd802b06656aaf14625369bbb0059219ca3f6b0121033cded59f3d05fe9cc406d0b19cafb070b9ae6ffd3107c13df1ef1a854d9a356efeffffff0ff1d9efac445a3316111567b062c1ec82b77c10ce980695e03d1d2086fb7062010000006b483045022100bf40ae1783cdf2181e34b7c3085f1a7450fc80eaefa69b69ddbaa92747d6c03d02200b7d34d6a49c1b891bdbb1e2d7b6765904c5666d208be4e71ac5492f1b1591e40121031103d18fc2c5cf2bb640d7ccac6bc6736200a4530f5830d4242deed71165c0c4feffffffae8d658ca74ba4e15eaea1468be86696b8d73a92e5e3fb3a1e1e1e8f554d4ca0010000006b483045022100bd2cf4df18d501b309ef672baae41b417729ecff9788dc94b820c13230eaa05502200a2b0b9ff6c7fc1a7209d49ec1d22f347a0b6b3b47f9589429ea82a82a706c24012102d8f70714bd8bd1f07ceaf57565c0dbe0a6546ec004438dd58186438f4977de80feffffff4cd33f56c62ebb19b0f7454b5a7939a01a0e4c0fe5c523880d7cc659b2d5786e010000006b483045022100ed76c4d5457f7bcbb082110b46a2e0450408baa5f32bf102beae996987f092a7022016eb432fb0e148bbcfa1af6ea8165275a5151ab6a7150a32eba3790b3e55c452012102619a78b50f170458b980a9696bc951f159e119cd73bb19780392fdf46817449bfeffffffec962594366326c07107cfb0e3598c914f09fb106cd640831f9f330e3ffa0a85010000006b48304502210092d40bf6a41d511ebfe694db36adbe9e22dcf2f971bb819136c5a7a87eaf2d620220206e87b1744688443707b6ffa77559c2b104c9217274cd94431203412464580a012103097e37278219f83bb89280e9c0591576688215e785099f291cfcf48ed715979afeffffffe2ce0726e9d1747e34c0fbb9a96ff976e07ce132b57da2f3e55272473852a893000000006a47304402201f950b574b2a76012607b528973f2e5683b89de7f64f8b3f432629c693f7fa9802205f3d8fc26113608bf72cb9f579d67534624b348669aff15aa40e152b1752140601210362a3354f35c84b485390800da154b98a774625e7f5292cdf1b632bf99bba6db8feffffff238f29ee383e41937b4a7c96343e1efa1b6a15e67e699cc90369a1a97742613b010000006a47304402203798236d4390dd5bcbc26d94c72159e42289eebb11d88f8f16b8694b519164b0022056d89b32b183565f4bfb8bc59c9f484d42b7ddbd604edc94892ccfc49547e5fb0121036e2267e2fc5e2c22b96bd5ce3eee13318a382bbff1c676bb64fe61d44abdda4ffeffffffd3bcfbab5a06bb60dca1732133a3c7739c52beebb5cb40c9a81cb5634cd76770010000006a473044022064c6afe6b7ff4a26a0b40be64ebdf9ae37278e694cc1c0681f90bc48d5f7678f02203a465b600b2e65bc2efe76224bda6684136d1a357c4bc584d7c6b6d4ba1f2b0c0121021e1393b19629ede188b0bfc4478e1fcd7177c019d8bcaacd6a2f675fae0092f8feffffff14c6c05e0e8f67c3f78621daf6cb8683c077d68940bfed5c897fb380183b73c8000000006b483045022100be0f8be5f4d37f4fa6f241b5b87f81c7acf0c120d90c75a584bd6205e91ce12a0220322ff2f7c4e6d685e1bf6bc5ecee52884a2288cec5159cf357cfb872b604085d0121034effb607fa934d731eb20deb24eef31975806aae37622f82a7d35e422c0c2a77feffffff88c8c32ccf207faf09b9d4bc6335a2603edce0ddf5e614a1d77ae899c668f093010000006a4730440220574a41772e32efa5cc7fe36810bc77791ab03b7fa57db6776a6ab6c81ffeeaab02206724c4ff24a684cf2eabd266172342427b2a737d53add0ba48ec7afa35b1c3ff012103b944413015db4ce1d5ea6b5ba0d296a1828ccb895dd44d3eceacd6f96769faa1feffffffdc08c4f91051cff96493c53bac524b5d6336b3424a19b2b3272545bb12112ce20100000069463043021f12956f83cb0638b7026e477c67065131bb97b64ef639e44caf3a55a19a2dbc02204525c7969d5007ea0e2d05a8e26c52a76906bb58e17dbc5b37a17be41be185950121023ff82f183e377f5792589ca85a169045a89a378cf1a5b609b509db38e7f21c57feffffff673adb3ac3cfb71459fd7f2fe63c39c555b0a2bf333497d979f85abdbda9c2d7010000006b4830450221009e5357ccee1ef4d9f345214c09727d26e458bb982cea5096a40f71ead5eed3cc0220725ebd4a56346c2cbafdf0dd04668b2bf45efbd348f173057de73c2cde8ddfb0012103671a75a97f3c6655cfd887901bf3a3f12159b535c73091e5389e5a4331aa4aa0feffffff1fc4456c8b60369f7e8412021f70b47a8e403f47d0a6ee83c9c0861efa70eee1000000006b483045022100b37f69e91b2b212d284fed9ff14fd27a5ebbfe9fa86d5141b203a528c43b3ebe02200e2c071946f73d779495e311aa8ce2b2e1eebebef3464dbf47aa92d73844c5ae012102f8c0bcea6a933caef671c157c40c46f816afc77aee0561990963caa1185b62a3feffffff2bcd7770a2386a7fb45a0363eb95566186c44403c8bab4e860604d357e5f0ef7010000006a47304402200101991530dc7b0ef6a1d2fdaaf66905261235780aaa3b7ebf3dd66b4bae0f3802204d313fbc1647345cf6e04c3bfd56579387fadd32a4c87e40afe58b374ac7d5f6012103c978c27fe43fc7af743ff9af0f08adf17758dd7bebc472e7a1fb65a3c3937a86fefffffff0f3418718057fe0775b6fa9d1e563b546d832e9faabd91d372772dca72b7e69010000006a47304402203e71f4fd4bbb623b8e436d7a8ebaea6f3ec7495a5080941d40dd5bfc30a3f8eb02200f52b9e8c17b485a287f44db9caafc9cb27933f9ea6cd13aad6a879c5adb1b81012102298d0bdfb88ba1b26373085c3a06ce592c04a77c227ebccaed5df1d6bc67d7f4feffffffb86f51e4a0cacaea0029ca0bd9539b86151295f80095aa6b5eb12429c065984e010000006b483045022100bdb80aaffc403931f85d31d49216dd0a828224beb97d250389651fb243214e58022075a393f3dbd47f7d4ea3ff186a3d3f3084053d3fe60ffa9403eed0f1d82350ed012103728f6713b8f71297e068f3c8a91e3b88ba5577f41f5bd05ca4712f215ab67b11feffffffcae15162bf46e24fa9853c98b06a97a37fb5ff65d31ec6c38586da44ea726828000000006b48304502210085cf629f198bd70ee60392172097c8de055d460b9f433f64dbd91708cc19904302202dc885238f618b68276f0c659907ff23ce0fe242e600d27987b2406db8673a79012102c17106c53a924f3143840a4d30663e86d13dfda8db776a8d15bdd24d8f520057feffffff07982523515d58d0b9194b8d961505ac566649ff0710a3281874ec89f0f63d62000000006b483045022100e81925698af948ea292ab766cca4321890df25e1cba4109ccfb16b7fdfcbfc4502203e38a4a2c073fee1ca3210a18b0bd2760abbcc9c8b7180cf8e960049d83f6b56012102334ea42910e73fde9d8faf9f9d53012c2a654abfc2676fcc3b3196171f90e8b8feffffff07e9cc38676c2716c05af414af1da92146a6b8f510ffbccd904141a02b11ea61000000006a47304402207dd13d80aba06b60d4fd5e5129c964de542ee6b85381d9fb00dd4128f2305e400220733ce1c1e79927ed33b4d7584c16d8264241f24696dafa43ff4b25b3a0b7423b012102334ea42910e73fde9d8faf9f9d53012c2a654abfc2676fcc3b3196171f90e8b8feffffff21464c5d7137dca4a2d06924e68a81579c91887dd4b845a159ef459d4d2a750f000000006a47304402202616405d7adc256732da51138c9cf4c916bee3cb4f870cf2c1c999638f2274f1022034ba2372d9b1e9d438507fea74b667b12e10ca5e39dd977b9eb11e221536df37012103df1add3b173c0d0a18b4f18e562ffa6bc5e6c3cca25a8424193265f02478cd6cfeffffff4a748dad587321be31172a9a471013b109bb920852f3721a727c40f179f2a77c000000006b483045022100bae51efb935bf688f00c46133e0a5a6be9597c8f84614bd97a90a1a0b077d9d202203a196ac74001d0582993f167c0f2c1a9a3d7443e2cc54851bb547744edff1cf2012102334ea42910e73fde9d8faf9f9d53012c2a654abfc2676fcc3b3196171f90e8b8feffffff5d2b41b0e49b154199a3f53fbb531525fdbc4cf3cbd791077b8c7694eeb7580a000000006a47304402202bb10cd2dd0090bc4b7aad6f24acffbf7b061ff331bbf09e75b743dc531e39d102201c0488b64caade0afde497f72a4385b81303a9f03e9e7a3415a634bedb8a2e25012102334ea42910e73fde9d8faf9f9d53012c2a654abfc2676fcc3b3196171f90e8b8feffffff70435426357fec44e290a43e57cf539ddf6bf7e4ff05f0ab2811ef14ce82d557000000006b483045022100899e90099c5907ae5a8e8fe44d3b458da6f80c783c8d4555afb5cf37e98bba5e022073b2f5fa177c56cd6f21d76d3b3f0897db2105f79dcc48b8ae819cb36a7d5ca2012102334ea42910e73fde9d8faf9f9d53012c2a654abfc2676fcc3b3196171f90e8b8feffffff8023120446dfc08d605cb026b402ced4e09c45ed93a19f07f6c9aae7cb669ad9000000006a47304402207fc18c16106e2bda868d75ff623793f305f73f9049f825d9556cc9035ccb61c202204e3a6e353a41dfed3e92a977cc09b02ec4095d727baffe6248884e341a0e9673012102334ea42910e73fde9d8faf9f9d53012c2a654abfc2676fcc3b3196171f90e8b8feffffff80f83e349e8518c64eff44c7de6e2ed6bc61bc758488a90bfa6bfbd78478ce95000000006b483045022100bc361a9940e1fa1396c956d077a84efe63eb13948042eb473e261d7822a625a00220721fd6bee5533115d1302f2ac66c982c522101ab6c2d17457c0ed47a27e5143e012102334ea42910e73fde9d8faf9f9d53012c2a654abfc2676fcc3b3196171f90e8b8feffffff8f3dcf3a35be291e87af3cfc7356364d7ff59379d0a8ccf94a04fa66a3ed2507000000006b483045022100cc5730728634e590163a5c45f3e3af4adf2093b339f42d603b97721b0029276802200d17603e59ab66bfcb1aecbdc2fc0f5c9ba5f03fda16d7c7eae5a71eac41c3ef012102334ea42910e73fde9d8faf9f9d53012c2a654abfc2676fcc3b3196171f90e8b8feffffffbba5446cbf993f73bce837e42476c34ea426bc014863acc34ac79f4da36476f2000000006a47304402206181fcd4104f310119e6a37d6b75f1fa001037b86df0b186e3127a32d5a3202302200d9fffea195eb8f2ab104507dcb0725a49dbbd00a8d79e8a582105b89535bc04012102334ea42910e73fde9d8faf9f9d53012c2a654abfc2676fcc3b3196171f90e8b8feffffffc11f776072e635f1658cf2313e1879018a372cca6b4d42ad029dedb1c1b8a905000000006a47304402207c46b1f4863972dfdac497493de83b9fb5d599db60b505d4f436532219b9ad6702200fd1b3027824de54736e35fe0640d570a3f9461e245308870d962744edf27e66012102334ea42910e73fde9d8faf9f9d53012c2a654abfc2676fcc3b3196171f90e8b8feffffffd02b8044edcaae52de83c792868156b11fcbb0a56f8d0b078f7346e48ca616c0000000006b483045022100ac393e865fb8f45d59c37749997d1836fc019141821650cb7b79a2df820129740220578047355da76d8e6235282cb10d437d8411934ef710bbfe8263f4d4ccceca50012102334ea42910e73fde9d8faf9f9d53012c2a654abfc2676fcc3b3196171f90e8b8feffffffd8ba9bdfb7e41f04000dcd13fb35a4274113efd83e38dfbff42ea642a3b6e6b7000000006a473044022031ad7aef51b8c448d6449c08d3884287642d38dba9e8987b7f0ddc23cf7c7cbf022010e6a88ec4db49c0e29f25268899dc2366dff7bc4a0eabdc3b5401bcf7f4d244012102334ea42910e73fde9d8faf9f9d53012c2a654abfc2676fcc3b3196171f90e8b8feffffffe67666a79bbc6a9833058118f64a9e30c7014f59f5e0d71046b59b6664f7c99d000000006b483045022100bf9e37873b2ad005a57c0deb1783ec2248da67cc9b13cdc8fe54a42156a3d9a202200c8c710d403eb4cd172a48c83049827efad897b581d631376452e65f9543bb09012102334ea42910e73fde9d8faf9f9d53012c2a654abfc2676fcc3b3196171f90e8b8fefffffff335d52d300de2f28f4ce9be2d0f24065638255c4e0268fddc7dd4491483b3c2000000006b483045022100ac4e2b2b774ac2b8a81d4c89237a8874d856a59e99e32bf3f35ddb5c9652875002205e286c33370f9852370adc4217ea06ae9beecef7b30083621c5f7f17d671e3e3012102334ea42910e73fde9d8faf9f9d53012c2a654abfc2676fcc3b3196171f90e8b8fefffffff5145234e256b8c813686e6f671a388a4d9a71c200481a6322d31ab787dae615000000006b4830450221008196b2a2f964655c88413346dc357bd0184c4df590eca7e9eaee0471331945d30220700c3f09007aa715f32b9051b5c95891319acdc3bfae0c2ac568a0516e24d2f3012102334ea42910e73fde9d8faf9f9d53012c2a654abfc2676fcc3b3196171f90e8b8fefffffff65ac1e554061580286bf7bb636474070682d09f91606d740e4b389c32854cf2000000006a47304402207793995576255949bb2b58dd342fc0da896482f696b91129e0c70dc270c9f2ec02204052b3cec406e6b8141a3c478e896c2abfb67019f047117b879ca39db1276244012102334ea42910e73fde9d8faf9f9d53012c2a654abfc2676fcc3b3196171f90e8b8feffffff020047fa71dd0000001976a914548f78d693b08cbed5e889d4b7c7c4f806231fa388ac1e691b00000000001976a914d8be7f443989d593c87bbc9b4d9ec916a42cf7f688ac3d8d1000");

    }
    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();

    private byte[] block1084745Bytes;
    private Block block1084745;

    @Before
    public void setUp() throws Exception {
        new Context(TESTNET);
        // One with some of transactions in, so a good test of the merkle tree hashing.
        block1084745Bytes = blockBytes;
        block1084745 = TESTNET.getDefaultSerializer().makeBlock(block1084745Bytes);
        assertEquals("000000001f1afc05cb4403f5776c863afd4c71da4e4ea184e43e41b25d071b15", block1084745.getHashAsString());
    }

    @Test
    public void testWork() throws Exception {
        BigInteger work = TESTNET.getGenesisBlock().getWork();
        double log2Work = Math.log(work.longValue()) / Math.log(2);
        // This number is printed by Groestlcoin Core at startup as the calculated value of chainWork on testnet:
        // SetBestChain: new best=00000ac5927c594d49cc  height=0  work=1048577
        assertEquals(20.0000014, log2Work,
                         0.0000001);
        //assertEquals(BigInteger.valueOf(1048577L), work);
    }

    @Test
    public void testBlockVerification() throws Exception {
        block1084745.verify(Block.BLOCK_HEIGHT_GENESIS, EnumSet.noneOf(Block.VerifyFlag.class));
    }
    
    @SuppressWarnings("deprecation")
    @Test
    public void testDate() throws Exception {
        assertEquals("9 May 2016 05:25:25 GMT", block1084745.getTime().toGMTString());
    }

    @Test
    public void testProofOfWork() throws Exception {
        // This params accepts any difficulty target.
        Block block = UNITTEST.getDefaultSerializer().makeBlock(block1084745Bytes);
        block.setNonce(123467);
        try {
            block.verify(Block.BLOCK_HEIGHT_GENESIS, EnumSet.noneOf(Block.VerifyFlag.class));
            fail();
        } catch (VerificationException e) {
            // Expected.
        }
        // Blocks contain their own difficulty target. The BlockChain verification mechanism is what stops real blocks
        // from containing artificially weak difficulties.
        block.setDifficultyTarget(Block.EASIEST_DIFFICULTY_TARGET);
        // Now it should pass.
        block.verify(Block.BLOCK_HEIGHT_GENESIS, EnumSet.noneOf(Block.VerifyFlag.class));
        // Break the nonce again at the lower difficulty level so we can try solving for it.
        block.setNonce(2);
        try {
            block.verify(Block.BLOCK_HEIGHT_GENESIS, EnumSet.noneOf(Block.VerifyFlag.class));
            fail();
        } catch (VerificationException e) {
            // Expected to fail as the nonce is no longer correct.
        }
        // Should find an acceptable nonce.
        block.solve();
        block.verify(Block.BLOCK_HEIGHT_GENESIS, EnumSet.noneOf(Block.VerifyFlag.class));
    }

    @Test
    public void testBadTransactions() throws Exception {
        // Re-arrange so the coinbase transaction is not first.
        Transaction tx1 = block1084745.transactions.get(0);
        Transaction tx2 = block1084745.transactions.get(1);
        block1084745.transactions.set(0, tx2);
        block1084745.transactions.set(1, tx1);
        try {
            block1084745.verify(Block.BLOCK_HEIGHT_GENESIS, EnumSet.noneOf(Block.VerifyFlag.class));
            fail();
        } catch (VerificationException e) {
            // We should get here.
        }
    }

    @Test
    public void testHeaderParse() throws Exception {
        Block header = block1084745.cloneAsHeader();
        Block reparsed = TESTNET.getDefaultSerializer().makeBlock(header.bitcoinSerialize());
        assertEquals(reparsed, header);
    }

    @Test
    public void testBitcoinSerialization() throws Exception {
        // We have to be able to reserialize everything exactly as we found it for hashing to work. This test also
        // proves that transaction serialization works, along with all its subobjects like scripts and in/outpoints.
        //
        // NB: This tests the bitcoin serialization protocol.
        assertTrue(Arrays.equals(block1084745Bytes, block1084745.bitcoinSerialize()));
    }
    
    @Test
    public void testUpdateLength() {
        Block block = UNITTEST.getGenesisBlock().createNextBlockWithCoinbase(Block.BLOCK_VERSION_GENESIS, new ECKey().getPubKey(), Block.BLOCK_HEIGHT_GENESIS);
        assertEquals(block.bitcoinSerialize().length, block.length);
        final int origBlockLen = block.length;
        Transaction tx = new Transaction(UNITTEST);
        // this is broken until the transaction has > 1 input + output (which is required anyway...)
        //assertTrue(tx.length == tx.bitcoinSerialize().length && tx.length == 8);
        byte[] outputScript = new byte[10];
        Arrays.fill(outputScript, (byte) ScriptOpCodes.OP_FALSE);
        tx.addOutput(new TransactionOutput(UNITTEST, null, Coin.SATOSHI, outputScript));
        tx.addInput(new TransactionInput(UNITTEST, null, new byte[] {(byte) ScriptOpCodes.OP_FALSE},
                new TransactionOutPoint(UNITTEST, 0, Sha256Hash.of(new byte[] { 1 }))));
        int origTxLength = 8 + 2 + 8 + 1 + 10 + 40 + 1 + 1;
        assertEquals(tx.unsafeBitcoinSerialize().length, tx.length);
        assertEquals(origTxLength, tx.length);
        block.addTransaction(tx);
        assertEquals(block.unsafeBitcoinSerialize().length, block.length);
        assertEquals(origBlockLen + tx.length, block.length);
        block.getTransactions().get(1).getInputs().get(0).setScriptBytes(new byte[] {(byte) ScriptOpCodes.OP_FALSE, (byte) ScriptOpCodes.OP_FALSE});
        assertEquals(block.length, origBlockLen + tx.length);
        assertEquals(tx.length, origTxLength + 1);
        block.getTransactions().get(1).getInputs().get(0).clearScriptBytes();
        assertEquals(block.length, block.unsafeBitcoinSerialize().length);
        assertEquals(block.length, origBlockLen + tx.length);
        assertEquals(tx.length, origTxLength - 1);
        block.getTransactions().get(1).addInput(new TransactionInput(UNITTEST, null, new byte[] {(byte) ScriptOpCodes.OP_FALSE},
                new TransactionOutPoint(UNITTEST, 0, Sha256Hash.of(new byte[] { 1 }))));
        assertEquals(block.length, origBlockLen + tx.length);
        assertEquals(tx.length, origTxLength + 41); // - 1 + 40 + 1 + 1
    }

    @Test
    public void testCoinbaseHeightTestnet() throws Exception {
        // Testnet block 21066 (hash 0000000004053156021d8e42459d284220a7f6e087bf78f30179c3703ca4eefa)
        // contains a coinbase transaction whose height is two bytes, which is
        // shorter than we see in most other cases.

        Block block = TESTNET.getDefaultSerializer().makeBlock(
            ByteStreams.toByteArray(getClass().getResourceAsStream("block_testnet21066.dat")));

        // Check block.
        assertEquals("0000000004053156021d8e42459d284220a7f6e087bf78f30179c3703ca4eefa", block.getHashAsString());
        block.verify(21066, EnumSet.of(Block.VerifyFlag.HEIGHT_IN_COINBASE));

        // Testnet block 32768 (hash 000000007590ba495b58338a5806c2b6f10af921a70dbd814e0da3c6957c0c03)
        // contains a coinbase transaction whose height is three bytes, but could
        // fit in two bytes. This test primarily ensures script encoding checks
        // are applied correctly.

        block = TESTNET.getDefaultSerializer().makeBlock(
            ByteStreams.toByteArray(getClass().getResourceAsStream("block_testnet32768.dat")));

        // Check block.
        assertEquals("000000007590ba495b58338a5806c2b6f10af921a70dbd814e0da3c6957c0c03", block.getHashAsString());
        block.verify(32768, EnumSet.of(Block.VerifyFlag.HEIGHT_IN_COINBASE));
    }

    @Test
    public void testReceiveCoinbaseTransaction() throws Exception {
        // Block 169482 (hash 0000000000000756935f1ee9d5987857b604046f846d3df56d024cdb5f368665)
        // contains coinbase transactions that are mining pool shares.
        // The private key MINERS_KEY is used to check transactions are received by a wallet correctly.

        // The address for this private key is 1GqtGtn4fctXuKxsVzRPSLmYWN1YioLi9y.
        final String MINING_PRIVATE_KEY = "5JDxPrBRghF1EvSBjDigywqfmAjpHPmTJxYtQTYJxJRHLLQA4mG";

        final long BLOCK_NONCE = 3973947400L;
        final Coin BALANCE_AFTER_BLOCK = Coin.valueOf(22223642);
        Block block169482 = MAINNET.getDefaultSerializer().makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block169482.dat")));

        // Check block.
        assertNotNull(block169482);
        block169482.verify(169482, EnumSet.noneOf(Block.VerifyFlag.class));
        assertEquals(BLOCK_NONCE, block169482.getNonce());

        StoredBlock storedBlock = new StoredBlock(block169482, BigInteger.ONE, 169482); // Nonsense work - not used in test.

        // Create a wallet contain the miner's key that receives a spend from a coinbase.
        ECKey miningKey = DumpedPrivateKey.fromBase58(MAINNET, MINING_PRIVATE_KEY).getKey();
        assertNotNull(miningKey);
        Context context = new Context(MAINNET);
        Wallet wallet = new Wallet(context);
        wallet.importKey(miningKey);

        // Initial balance should be zero by construction.
        assertEquals(Coin.ZERO, wallet.getBalance());

        // Give the wallet the first transaction in the block - this is the coinbase tx.
        List<Transaction> transactions = block169482.getTransactions();
        assertNotNull(transactions);
        wallet.receiveFromBlock(transactions.get(0), storedBlock, NewBlockType.BEST_CHAIN, 0);

        // Coinbase transaction should have been received successfully but be unavailable to spend (too young).
        assertEquals(BALANCE_AFTER_BLOCK, wallet.getBalance(BalanceType.ESTIMATED));
        assertEquals(Coin.ZERO, wallet.getBalance(BalanceType.AVAILABLE));
    }

    @Test
    public void testBlock481815_witnessCommitmentInCoinbase() throws Exception {
        Block block481815 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block481815.dat")));
        assertEquals(2097, block481815.getTransactions().size());
        assertEquals("f115afa8134171a0a686bfbe9667b60ae6fb5f6a439e0265789babc315333262",
                block481815.getMerkleRoot().toString());

        // This block has no witnesses.
        for (Transaction tx : block481815.getTransactions())
            assertFalse(tx.hasWitnesses());

        // Nevertheless, there is a witness commitment (but no witness reserved).
        Transaction coinbase = block481815.getTransactions().get(0);
        assertEquals("919a0df2253172a55bebcb9002dbe775b8511f84955b282ca6dae826fdd94f90", coinbase.getTxId().toString());
        assertEquals("919a0df2253172a55bebcb9002dbe775b8511f84955b282ca6dae826fdd94f90",
                coinbase.getWTxId().toString());
        Sha256Hash witnessCommitment = coinbase.findWitnessCommitment();
        assertEquals("3d03076733467c45b08ec503a0c5d406647b073e1914d35b5111960ed625f3b7", witnessCommitment.toString());
    }

    @Test
    public void testBlock481829_witnessTransactions() throws Exception {
        Block block481829 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block481829.dat")));
        assertEquals(2020, block481829.getTransactions().size());
        assertEquals("f06f697be2cac7af7ed8cd0b0b81eaa1a39e444c6ebd3697e35ab34461b6c58d",
                block481829.getMerkleRoot().toString());
        assertEquals("0a02ddb2f86a14051294f8d98dd6959dd12bf3d016ca816c3db9b32d3e24fc2d",
                block481829.getWitnessRoot().toString());

        Transaction coinbase = block481829.getTransactions().get(0);
        assertEquals("9c1ab453283035800c43eb6461eb46682b81be110a0cb89ee923882a5fd9daa4", coinbase.getTxId().toString());
        assertEquals("2bbda73aa4e561e7f849703994cc5e563e4bcf103fb0f6fef5ae44c95c7b83a6",
                coinbase.getWTxId().toString());
        Sha256Hash witnessCommitment = coinbase.findWitnessCommitment();
        assertEquals("c3c1145d8070a57e433238e42e4c022c1e51ca2a958094af243ae1ee252ca106", witnessCommitment.toString());
        byte[] witnessReserved = coinbase.getInput(0).getWitness().getPush(0);
        assertEquals("0000000000000000000000000000000000000000000000000000000000000000", HEX.encode(witnessReserved));
        block481829.checkWitnessRoot();
    }

    @Test
    public void isBIPs() throws Exception {
        final Block genesis = MAINNET.getGenesisBlock();
        assertFalse(genesis.isBIP34());
        assertFalse(genesis.isBIP66());
        assertFalse(genesis.isBIP65());

        // 227835/00000000000001aa077d7aa84c532a4d69bdbff519609d1da0835261b7a74eb6: last version 1 block
        final Block block227835 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block227835.dat")));
        assertFalse(block227835.isBIP34());
        assertFalse(block227835.isBIP66());
        assertFalse(block227835.isBIP65());

        // 227836/00000000000000d0dfd4c9d588d325dce4f32c1b31b7c0064cba7025a9b9adcc: version 2 block
        final Block block227836 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block227836.dat")));
        assertTrue(block227836.isBIP34());
        assertFalse(block227836.isBIP66());
        assertFalse(block227836.isBIP65());

        // 363703/0000000000000000011b2a4cb91b63886ffe0d2263fd17ac5a9b902a219e0a14: version 3 block
        final Block block363703 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block363703.dat")));
        assertTrue(block363703.isBIP34());
        assertTrue(block363703.isBIP66());
        assertFalse(block363703.isBIP65());

        // 383616/00000000000000000aab6a2b34e979b09ca185584bd1aecf204f24d150ff55e9: version 4 block
        final Block block383616 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block383616.dat")));
        assertTrue(block383616.isBIP34());
        assertTrue(block383616.isBIP66());
        assertTrue(block383616.isBIP65());

        // 370661/00000000000000001416a613602d73bbe5c79170fd8f39d509896b829cf9021e: voted for BIP101
        final Block block370661 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block370661.dat")));
        assertTrue(block370661.isBIP34());
        assertTrue(block370661.isBIP66());
        assertTrue(block370661.isBIP65());
    }

    @Test
    public void parseBlockWithHugeDeclaredTransactionsSize() throws Exception{
        Block block = new Block(UNITTEST, 1, Sha256Hash.ZERO_HASH, Sha256Hash.ZERO_HASH, 1, 1, 1, new ArrayList<Transaction>()) {
            @Override
            protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
                Utils.uint32ToByteStreamLE(getVersion(), stream);
                stream.write(getPrevBlockHash().getReversedBytes());
                stream.write(getMerkleRoot().getReversedBytes());
                Utils.uint32ToByteStreamLE(getTimeSeconds(), stream);
                Utils.uint32ToByteStreamLE(getDifficultyTarget(), stream);
                Utils.uint32ToByteStreamLE(getNonce(), stream);

                stream.write(new VarInt(Integer.MAX_VALUE).encode());
            }

            @Override
            public byte[] bitcoinSerialize() {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                try {
                    bitcoinSerializeToStream(baos);
                } catch (IOException e) {
                }
                return baos.toByteArray();
            }
        };
        byte[] serializedBlock = block.bitcoinSerialize();
        try {
            UNITTEST.getDefaultSerializer().makeBlock(serializedBlock, serializedBlock.length);
            fail("We expect ProtocolException with the fixed code and OutOfMemoryError with the buggy code, so this is weird");
        } catch (ProtocolException e) {
            //Expected, do nothing
        }
    }
}
