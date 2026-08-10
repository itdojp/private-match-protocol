# SPDX-License-Identifier: Apache-2.0
"""Fixed SHA-256 authority for every published PET v0.2 artifact."""

from pathlib import Path

PUBLISHED_V02_DIGESTS = {
    Path(
        "config/pet-contract-compatibility.v0.2.json"
    ): "sha256:5505ea7bf62ff2db766f8333e700c0d39e7197904780e1410d182915c2c849f4",
    Path(
        "config/pet-profile-error-codes.v0.2.json"
    ): "sha256:1e1be608b5d8d71aaf63981891748611f1c45f0a76d5f5cc90b97fb70810128b",
    Path(
        "conformance/pet-profiles/case-catalog.v0.2.json"
    ): "sha256:b34a6f8bd0f652d63418485aed9574dde9f4691a8565893670dfeb90ea83e88e",
    Path(
        "conformance/pet-profiles/messages/result-acceptance-notice.v0.2.json"
    ): "sha256:e910c1b1de5a760d1e94fb3bedc20d60ef3464907df4d110738533f497f1970f",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-commitments-pending.v0.2.json"
    ): "sha256:4d0fb30ce6fa15b94a73bb9897cb7dbc7644adbd6fcf2ecfa2942a246a908fd0",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-committed.v0.2.json"
    ): "sha256:2537ba93dd8f3e8dbe12456b6c8e660735a982109a63ab5922e2b6d6b99fae7e",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-consent-pending.v0.2.json"
    ): "sha256:47428a15215b0dc505a0bc52963235a79c87a13ace8dce287a076972321b43b0",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-created.v0.2.json"
    ): "sha256:28f84dd7501d4be9a2dcbcd140df7a96c04b2eb4236a9eee1a27b228011cb726",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-disclosure-authorized.v0.2.json"
    ): "sha256:8d18196817f836a1643c91230724b15814670d6efbfd3d5fdcc2ad769c7321bd",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-evaluating-ack-a.v0.2.json"
    ): "sha256:82759c1713a2ac8223fc59029e3c8918dc286915e1dc20491a7b3b55ee8b1be1",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-evaluating-ack-b.v0.2.json"
    ): "sha256:00c66a1569ea9ee7dfe750a26def46ad6773fe707af4995c8ccebeeed52dc32c",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-evaluating-ack-both.v0.2.json"
    ): "sha256:86b39279f97f21b82ff88adb523a293c08afe0767b8304125bfe92c861562a6b",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-evaluating-contribution-a-only.v0.2.json"
    ): "sha256:00b35f713f8ff541f283acd53a1983e14ae6a1fe53967cbca5305ff3a42a1560",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-evaluating-contribution-b-only.v0.2.json"
    ): "sha256:5fbf2fadeac1711ded8f9c2f2bc0f3bc275aa43857eeaa714a6a50798777ecca",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-evaluating-contributions-none.v0.2.json"
    ): "sha256:e7f0774a04435afb89b2bded311f9d114f1a6b5a9d1cf693bbdc7f562deb73d7",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-participants-bound.v0.2.json"
    ): "sha256:1882ee3c399a06ba92f7c3231076a9d323634b686acd0898f1a7c17e01674c35",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-result-accepted.v0.2.json"
    ): "sha256:0451b27a081b3359fc46478c6b338bd766d7f6ee77123c5ea3d32bfc02a29be3",
    Path(
        "generated/pet-integration/cases/pet-valid-cancellation-cleanup.v0.2.json"
    ): "sha256:ae6aa3b81d98a57a28a8f012fd8e7e6d3f81f1285378bed34b42e521261aeee9",
    Path(
        "generated/pet-integration/cases/pet-valid-contribution-a.v0.2.json"
    ): "sha256:2649a6785cc00a476fad792378e56931a12fa71ce9a8d7bfe7e36d900f83a357",
    Path(
        "generated/pet-integration/cases/pet-valid-contribution-b.v0.2.json"
    ): "sha256:01c98c9fc1d6c4a171de129563dc01995a581167e2f42aab7f9229cb7ea4fbc3",
    Path(
        "generated/pet-integration/cases/pet-valid-evaluation-start.v0.2.json"
    ): "sha256:3345c86202bbdd63cd80046afaaf0bb775b2fbbb9d2ab2afb9fd67faa4eb473a",
    Path(
        "generated/pet-integration/cases/pet-valid-evaluation-timeout.v0.2.json"
    ): "sha256:5d77d95cbac4d702d595e5000a99725cd9b36b32e28f469ad2670eb3f2af9742",
    Path(
        "generated/pet-integration/cases/pet-valid-nitro-selection.v0.2.json"
    ): "sha256:27fadbe902ab0b67a09d2eac14ccb7abed3c76d09f377c93721f894ea64054e5",
    Path(
        "generated/pet-integration/cases/pet-valid-profile-callback.v0.2.json"
    ): "sha256:23fe2890538e955ccd456ce83d8c11d8b59150bcc051c44c416d818cc9bc8e02",
    Path(
        "generated/pet-integration/cases/pet-valid-query-budget.v0.2.json"
    ): "sha256:4c4108f56364e92e8a24e67a133e670349d1cbe4056d3991e44a8712dda8ada6",
    Path(
        "generated/pet-integration/cases/pet-valid-receipt-a.v0.2.json"
    ): "sha256:86dbc689a700950a1eeeaf074e3d57f5c96fbb6fb08e00095f58aaca4828360a",
    Path(
        "generated/pet-integration/cases/pet-valid-receipt-b.v0.2.json"
    ): "sha256:b1f33d1f1f796956c781ce240cb877b38747c26509591937e9a362118dfbdc54",
    Path(
        "generated/pet-integration/cases/pet-valid-secretflow-selection.v0.2.json"
    ): "sha256:b7c5403d9d109fb2dcc3637e6a096631655503a7447bd332f48ba06b67759161",
    Path(
        "generated/pet-integration/cases/pet-valid-voprf-registration.v0.2.json"
    ): "sha256:fb9a558354b55080f6b4de3082300046a0d86df8d85a945f294a81b0feb06523",
    Path(
        "generated/pet-integration/executable-case-results.v0.2.json"
    ): "sha256:bba1112b2a285012daa41642e4efc4e57e9d94def9d73be304b1b801af15ac6b",
    Path(
        "generated/pet-integration/product-handoff-projection.v0.2.json"
    ): "sha256:40ca8da6ad2be24599e103e4751664afdac3a5a68d51024815e64d243fb509b7",
    Path(
        "generated/pet-integration/profile-comparison.v0.2.md"
    ): "sha256:9aa99e3aa65a529712cd79393c8f9ae330e3a13615f75b1c7f1ae61dacdc4c8f",
    Path(
        "generated/pet-integration/profile-digest-manifest.v0.2.json"
    ): "sha256:27503e8254bf452d4ee166736f81970000e59fe99d024e938074a0c1ffafcf11",
    Path(
        "generated/pet-integration/profile-index.v0.2.json"
    ): "sha256:2f9de5c3cbe618328082abcea57a4b4d469b8db529083d49fe4b7ff581f946b0",
    Path(
        "handoff/product-decision-engine-port.v0.2.yaml"
    ): "sha256:32270ea25d6778e19834bc1c916611ffe745e2dbba6de615b1bc18fcf74552ca",
    Path(
        "profiles/pet-integration/nitro-enclave.v0.2.json"
    ): "sha256:035106cfe0bab5c1327290d7fc7afe316955bff1dd097f02775d1e4b41fefd23",
    Path(
        "profiles/pet-integration/secretflow-kkrt.v0.2.json"
    ): "sha256:551950c540bc5751de3825625766b7d67d8f70a066b8c77451bc70149a5152cc",
    Path(
        "profiles/pet-integration/voprf-component.v0.2.json"
    ): "sha256:136af23eee78eb5a0b9615c920a76d4ca6621e413ea7fa3a5dcc3ebb2281d832",
    Path(
        "registry/pet-integration-profiles.v0.2.yaml"
    ): "sha256:6b291247c8148fdb1cfc4d0b1c83cd4c24144d9be593f99d10d8620dffeac0d6",
    Path(
        "schema/pet-contract-compatibility.v0.2.schema.json"
    ): "sha256:df6c59da46ff1fe0c04f68addf0651cfc64fa188667f58a797a553b33c964999",
    Path(
        "schema/pet-integration-profile-registry.v0.2.schema.json"
    ): "sha256:881aecfc8900dfdf78089a01eda9c1b2a60f533ab9c25e327b5777fbf0bdf4d7",
    Path(
        "schema/pet-integration-profile.v0.2.schema.json"
    ): "sha256:30404a21accc1a9068e239aede75e9b5f2178b8ae95c7903192ecde801c92528",
    Path(
        "schema/pet-operation-stage-contract.v0.2.schema.json"
    ): "sha256:1d0900fb85332158041211ad7647c690f353b048332f314a971d44f504b0cdaf",
    Path(
        "schema/pet-profile-case-results.v0.2.schema.json"
    ): "sha256:ecc10ce269b2c406abceebac336f74f8c1396fd779864653538b6311150d168d",
    Path(
        "schema/pet-profile-conformance-cases.v0.2.schema.json"
    ): "sha256:6794e24f970a90a10990b6e469ac834ed82173cf8e8c93f43f286a8d736f3b13",
    Path(
        "schema/pet-profile-error-codes.v0.2.schema.json"
    ): "sha256:c2a3ffb3398f7eefdf027312163b837528cfdde38dfd65370d8c4699fc45958f",
    Path(
        "schema/pet-profile-operation-input.v0.2.schema.json"
    ): "sha256:36054fde5ffa210c67abfb2a192528d67f059c20f93ec13e624c158c68ddb4f9",
    Path(
        "schema/pet-protocol-binding.v0.2.schema.json"
    ): "sha256:ed7861f46c96985c49e32b162720bd55cba34e6240be4f1ec711b5d03fb73963",
    Path(
        "schema/product-decision-engine-handoff.v0.2.schema.json"
    ): "sha256:0869446c480db338aa68e35a9b7f3210887c9817d0cb570eaf1c4d5ea9bc0dc5",
    Path(
        "schemas/messages/envelope.v0.2.schema.json"
    ): "sha256:dd3facde469ee2539137d12527533210aa2014f77e3f18bfbe54a620f04e4e17",
    Path(
        "specs/pet-integration/nitro-enclave-v0.2.md"
    ): "sha256:7d9b01f3ac6bfb3d88576e59798fd8b15a05306012567f59037ce1a64b7607ca",
    Path(
        "specs/pet-integration/operation-stage-contract.v0.2.yaml"
    ): "sha256:5503bc6fdd994dbf79a7ba4b83167a9fc4b9eeb09ddd677cbfbe24bcb193dcd1",
    Path(
        "specs/pet-integration/protocol-binding.v0.2.yaml"
    ): "sha256:9b7f49c2a365fdc7b010ea85533512beeef25e44ae0691dd0dea083b5e984928",
    Path(
        "specs/pet-integration/secretflow-kkrt-v0.2.md"
    ): "sha256:6ab3ac2192134d1c19604c9318d27ea3f53532cabefd0a9ff8cd696fe85f59d0",
    Path(
        "specs/pet-integration/voprf-component-v0.2.md"
    ): "sha256:39a6a652b6d7e890fb440c2487dda8a7235d60dbcafb49af381051bd60158d70",
}
