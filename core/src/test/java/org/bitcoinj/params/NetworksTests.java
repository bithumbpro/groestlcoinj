/*
 * Copyright 2014 Giannis Dzegoutanis
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

package org.bitcoinj.params;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class NetworksTests {
    @Test
    public void networkFamily() throws Exception {
        class PeercoinDummy extends MainNetParams {
            PeercoinDummy() {
                super();
                id = "peercoin.main";
            }
        }
        class NubitsDummy extends MainNetParams {
            NubitsDummy() {
                super();
                id = "nubits.main";
            }
        }
        class NusharesDummy extends MainNetParams {
            NusharesDummy() {
                super();
                id = "nushares.main";
            }
        }
        class ReddcoinDummy extends MainNetParams {
            ReddcoinDummy() {
                super();
                id = "reddcoin.main";
            }
        }

        assertEquals(Networks.Family.PEERCOIN, Networks.getFamily(new PeercoinDummy()));
        assertEquals(Networks.Family.NUBITS, Networks.getFamily(new NubitsDummy()));
        assertEquals(Networks.Family.NUBITS, Networks.getFamily(new NusharesDummy()));
        assertEquals(Networks.Family.BITCOIN, Networks.getFamily(MainNetParams.get()));
        assertEquals(Networks.Family.REDDCOIN, Networks.getFamily(new ReddcoinDummy()));
    }
}
