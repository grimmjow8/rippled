//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright 2014 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include <BeastConfig.h>
#include <beast/http/dynamic_body.hpp>
#include <ripple/overlay/impl/TMHello.h>
#include <ripple/beast/unit_test.h>
#include <ripple/protocol/PublicKey.h>
#include <ripple/protocol/SecretKey.h>

#include <ripple/crypto/csprng.h>
#include <ripple/protocol/Seed.h>
#include <ripple/beast/utility/rngfill.h>
#include <algorithm>
#include <string>
#include <vector>
#include <ripple/protocol/impl/secp256k1.h>


namespace ripple {

class TMHello_test : public beast::unit_test::suite
{
private:
    using request_type =
        //beast::http::request<beast::http::empty_body>;
        beast::http::response<beast::http::dynamic_body>;
    request_type h;


    template <class FwdIt>
    static
    std::string
    join (FwdIt first, FwdIt last, char c = ',')
    {
        std::string result;
        if (first == last)
            return result;
        result = to_string(*first++);
        while(first != last)
            result += "," + to_string(*first++);
        return result;
    }

    void
    check(std::string const& s, std::string const& answer)
    {
        auto const result = parse_ProtocolVersions(s);
        BEAST_EXPECT(join(result.begin(), result.end()) == answer);
    }

public:
    void
    test_protocolVersions()
    {
        check("", "");
        check("RTXP/1.0", "1.0");
        check("RTXP/1.0, Websocket/1.0", "1.0");
        check("RTXP/1.0, RTXP/1.0", "1.0");
        check("RTXP/1.0, RTXP/1.1", "1.0,1.1");
        check("RTXP/1.1, RTXP/1.0", "1.0,1.1");
    }

    void
    test_appendHello()
    {
        beast::http::request<beast::http::empty_body> h;

        protocol::TMHello hello;

        // TODO initialize to some val
        SecretKey sk = generateSecretKey(KeyType::secp256k1, generateSeed ("masterpassphrase"));
        PublicKey pk = derivePublicKey(KeyType::secp256k1, sk);


        uint256 shared = beast::zero;

        auto const sig = signDigest (pk, sk, shared);
        hello.set_nodepublic (
            toBase58 (
                TokenType::TOKEN_NODE_PUBLIC,
                pk));
        hello.set_nodeproof (sig.data(), sig.size());
        appendHello(h, hello);

        auto const iter = h.find ("Session-Signature");
        if (iter == h.end())
            BEAST_EXPECT(0)
        BEAST_EXPECT((iter->value().to_string == "masterpassphrase"));


    // h.set_protoversion (to_packed (BuildInfo::getCurrentProtocol()));
    // h.set_protoversionmin (to_packed (BuildInfo::getMinimumProtocol()));
    // h.set_fullversion (BuildInfo::getFullVersionString ());
    // h.set_nettime (app.timeKeeper().now().time_since_epoch().count());


    // h.set_ipv4port (portNumber); // ignored now
    // h.set_testnet (false);

    // if (remote.is_v4())
    // {
    //     auto addr = remote.to_v4 ();
    //     if (is_public (addr))
    //     {
    //         // Connection is to a public IP
    //         h.set_remote_ip (addr.value);
    //         if (public_ip != beast::IP::Address())
    //             h.set_local_ip (public_ip.to_v4().value);
    //     }
    // }

    // // We always advertise ourselves as private in the HELLO message. This
    // // suppresses the old peer advertising code and allows PeerFinder to
    // // take over the functionality.
    // h.set_nodeprivate (true);

    // auto const closedLedger = app.getLedgerMaster().getClosedLedger();

    // assert(! closedLedger->open());
    // // VFALCO There should ALWAYS be a closed ledger
    // if (closedLedger)
    // {
    //     uint256 hash = closedLedger->info().hash;
    //     h.set_ledgerclosed (hash.begin (), hash.size ());
    //     hash = closedLedger->info().parentHash;
    //     h.set_ledgerprevious (hash.begin (), hash.size ());
    // }




    }

    void
    run()
    {
        test_protocolVersions();
        test_appendHello();
    }
};

BEAST_DEFINE_TESTSUITE(TMHello,overlay,ripple);

}
