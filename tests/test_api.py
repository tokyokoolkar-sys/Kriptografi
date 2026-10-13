"""HTTP API: every endpoint exercised through the ASGI test client."""

from __future__ import annotations

import pytest

from kriptografi.hashes import hmac_sha256, sha256


class TestMeta:
    def test_root(self, client):
        response = client.get("/")
        assert response.status_code == 200
        body = response.json()
        assert body["name"] == "Kriptografi API"
        assert "endpoints" in body

    def test_health(self, client):
        assert client.get("/health").json()["status"] == "ok"

    def test_openapi_schema_builds(self, client):
        response = client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert schema["info"]["title"] == "Kriptografi API"
        # Every route group must be documented.
        for prefix in ("/math", "/classical", "/transposition", "/block",
                       "/hash", "/rsa", "/dh", "/ecc"):
            assert any(path.startswith(prefix) for path in schema["paths"]), prefix


class TestMathEndpoints:
    def test_gcd_returns_full_euclid_chain(self, client):
        response = client.post("/math/gcd", json={"a": 1071, "b": 462})
        assert response.status_code == 200
        body = response.json()
        assert body["gcd"] == 21
        assert body["steps"][0]["equation"] == "1071 = 2*462 + 147"

    def test_gcd_rejects_both_zero(self, client):
        assert client.post("/math/gcd", json={"a": 0, "b": 0}).status_code == 400

    def test_mod_inverse(self, client):
        response = client.post("/math/mod-inverse", json={"a": 3, "m": 7})
        body = response.json()
        assert body["inverse"] == 5
        assert "3" in body["verification"]

    def test_mod_inverse_rejects_non_coprime(self, client):
        response = client.post("/math/mod-inverse", json={"a": 6, "m": 9})
        assert response.status_code == 400
        assert "no modular inverse" in response.json()["detail"]

    def test_crt(self, client):
        response = client.post("/math/crt", json={"residues": [2, 3, 2], "moduli": [3, 5, 7]})
        body = response.json()
        assert body["solution"] == 23
        assert body["modulus_product"] == 105
        assert all(step["satisfies"] for step in body["steps"])

    def test_crt_rejects_mismatched_lengths(self, client):
        assert client.post("/math/crt", json={"residues": [1, 2], "moduli": [3]}).status_code == 400

    def test_primality_prime(self, client):
        assert client.post("/math/primality", json={"n": 7919}).json()["is_prime"] is True

    def test_primality_composite_includes_factors(self, client):
        body = client.post("/math/primality", json={"n": 360}).json()
        assert body["is_prime"] is False
        assert body["factorization"] == [2, 2, 2, 3, 3, 5]

    def test_factorize(self, client):
        body = client.post("/math/factorize", json={"n": 360}).json()
        assert body["factors"] == [2, 2, 2, 3, 3, 5]

    def test_factorize_refuses_huge_numbers(self, client):
        response = client.post("/math/factorize", json={"n": 10**20})
        assert response.status_code == 400
        assert "trial division" in response.json()["detail"]

    def test_powmod_trace(self, client):
        body = client.post("/math/powmod", json={"base": 4, "exponent": 13, "modulus": 497}).json()
        assert body["result"] == 445
        assert body["binary_exponent"] == "1101"
        assert len(body["steps"]) == 4

    def test_totient(self, client):
        assert client.post("/math/totient", json={"n": 100}).json()["phi"] == 40

    def test_discrete_log(self, client):
        response = client.get("/math/discrete-log",
                              params={"base": 2, "target": pow(2, 37, 101), "modulus": 101})
        body = response.json()
        assert body["solution_exists"] is True
        assert pow(2, body["discrete_log"], 101) == pow(2, 37, 101)

    def test_verify_powmod(self, client):
        response = client.get("/math/verify-powmod",
                              params={"base": 4, "exponent": 13, "modulus": 497, "expected": 445})
        assert response.json()["matches"] is True

    def test_verify_powmod_detects_wrong_answer(self, client):
        response = client.get("/math/verify-powmod",
                              params={"base": 4, "exponent": 13, "modulus": 497, "expected": 444})
        assert response.json()["matches"] is False


class TestClassicalEndpoints:
    def test_caesar_round_trip_through_api(self, client):
        encrypted = client.post("/classical/caesar/encrypt",
                                json={"text": "HALLO 2026", "shift": 3}).json()
        assert encrypted["result"] == "KDOORC5359"
        assert encrypted["alphabet_size"] == 37

        decrypted = client.post("/classical/caesar/decrypt",
                                json={"text": encrypted["result"], "shift": 3}).json()
        assert decrypted["result"] == "HALLO 2026"

    def test_vigenere_round_trip(self, client):
        encrypted = client.post("/classical/vigenere",
                                json={"text": "HELLOWORLD", "key": "KEY"}).json()
        decrypted = client.post("/classical/vigenere",
                                json={"text": encrypted["result"], "key": "KEY",
                                      "operation": "decrypt"}).json()
        assert decrypted["result"] == "HELLOWORLD"

    def test_vigenere_rejects_empty_key(self, client):
        response = client.post("/classical/vigenere", json={"text": "HI", "key": " "})
        assert response.status_code == 400

    def test_beaufort_round_trip(self, client):
        encrypted = client.post("/classical/beaufort",
                                json={"text": "HELLOWORLD", "key": "KEY"}).json()
        decrypted = client.post("/classical/beaufort",
                                json={"text": encrypted["result"], "key": "KEY"}).json()
        assert decrypted["result"] == "HELLOWORLD"

    def test_autokey_round_trip(self, client):
        encrypted = client.post("/classical/autokey",
                                json={"text": "ATTACKATDAWN", "key": "KEY"}).json()
        decrypted = client.post("/classical/autokey",
                                json={"text": encrypted["result"], "key": "KEY",
                                      "operation": "decrypt"}).json()
        assert decrypted["result"] == "ATTACKATDAWN"

    def test_affine_round_trip(self, client):
        encrypted = client.post("/classical/affine",
                                json={"text": "HELLO", "a": 5, "b": 8}).json()
        decrypted = client.post("/classical/affine",
                                json={"text": encrypted["result"], "a": 5, "b": 8,
                                      "operation": "decrypt"}).json()
        assert decrypted["result"] == "HELLO"

    def test_affine_rejects_singular_a(self, client):
        response = client.post("/classical/affine", json={"text": "HI", "a": 0, "b": 3})
        assert response.status_code == 400

    def test_affine_key_listing(self, client):
        body = client.get("/classical/affine/keys").json()
        assert body["count"] == 1332
        assert body["modulus"] == 37

    def test_playfair_round_trip(self, client):
        encrypted = client.post("/classical/playfair",
                                json={"text": "HELLOWORLD", "key": "KEYWORD"}).json()
        assert encrypted["result"] == "GYIZSCOKCFBU"

        decrypted = client.post("/classical/playfair",
                                json={"text": encrypted["result"], "key": "KEYWORD",
                                      "operation": "decrypt"}).json()
        # Playfair inserts X between doubled letters, so 'HELLOWORLD' returns as
        # 'HELXLOWORLDX'. Removing the fillers must recover the original exactly.
        assert decrypted["result"] == "HELXLOWORLDX"
        assert decrypted["result"].replace("X", "") == "HELLOWORLD"

    def test_playfair_rejects_empty_key(self, client):
        assert client.post("/classical/playfair",
                           json={"text": "HI", "key": ""}).status_code == 400

    def test_hill_round_trip(self, client):
        matrix = [[3, 3], [2, 5]]
        encrypted = client.post("/classical/hill",
                                json={"text": "HELLOWORLD", "matrix": matrix}).json()
        assert encrypted["result"] == "783D81TCFA"

        decrypted = client.post("/classical/hill",
                                json={"text": encrypted["result"], "matrix": matrix,
                                      "operation": "decrypt"}).json()
        assert decrypted["result"] == "HELLOWORLD"

    def test_hill_rejects_singular_matrix(self, client):
        response = client.post("/classical/hill",
                               json={"text": "HELLO", "matrix": [[1, 2], [2, 4]],
                                     "operation": "decrypt"})
        assert response.status_code == 400

    def test_hill_rejects_non_square_matrix(self, client):
        response = client.post("/classical/hill",
                               json={"text": "HELLO", "matrix": [[1, 2, 3], [4, 5, 6]]})
        assert response.status_code == 400


class TestTranspositionEndpoints:
    def test_rail_fence_round_trip(self, client):
        text = "WEAREDISCOVEREDFLEEATONCE"
        encrypted = client.post("/transposition/rail-fence/encrypt",
                                json={"text": text, "rails": 3}).json()
        assert encrypted["result"] == "WECRLTEERDSOEEFEAOCAIVDEN"

        decrypted = client.post("/transposition/rail-fence/decrypt",
                                json={"text": encrypted["result"], "rails": 3}).json()
        assert decrypted["result"] == text

    def test_rail_fence_rejects_single_rail(self, client):
        assert client.post("/transposition/rail-fence/encrypt",
                           json={"text": "HI", "rails": 1}).status_code == 422

    def test_columnar_round_trip(self, client):
        text = "WEAREDISCOVEREDFLEEATONCE"
        encrypted = client.post("/transposition/columnar",
                                json={"text": text, "key": "ZEBRA"}).json()
        assert encrypted["result"] == "EODAEASRENEIELORCEECWDVFT"

        decrypted = client.post("/transposition/columnar",
                                params={"operation": "decrypt"},
                                json={"text": encrypted["result"], "key": "ZEBRA"}).json()
        assert decrypted["result"] == text

    def test_row_transposition_round_trip(self, client):
        text = "WEAREDISCOVEREDFLEEATONCE"
        encrypted = client.post("/transposition/row",
                                json={"text": text, "key": "ZEBRA", "columns": 5}).json()

        decrypted = client.post("/transposition/row",
                                params={"operation": "decrypt"},
                                json={"text": encrypted["result"], "key": "ZEBRA",
                                      "columns": 5}).json()
        assert decrypted["result"] == text

    def test_frequency_analysis(self, client):
        body = client.get("/transposition/analysis/frequency",
                          params={"text": "AABBBCC"}).json()
        assert body["most_common"] == "B"
        assert body["ranking"] == ["B", "A", "C"]

    def test_index_of_coincidence_english(self, client):
        body = client.get("/transposition/analysis/ic",
                          params={"text": "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"}).json()
        # English text sits near 0.066; on a 43-character sample the estimate is
        # noisy, so assert it is clearly above the random-text baseline of ~0.026.
        assert 0.035 < body["index_of_coincidence"] < 0.12

    def test_crack_caesar_finds_the_key(self, client):
        plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND THEN RUNS AWAY"
        ciphertext = client.post("/classical/caesar/encrypt",
                                 json={"text": plaintext, "shift": 7}).json()["result"]

        results = client.get("/transposition/analysis/crack-caesar",
                             params={"text": ciphertext, "top": 3}).json()["results"]
        assert results[0]["shift"] == 7
        assert results[0]["plaintext"] == plaintext

    def test_crack_vigenere_finds_key_length(self, client):
        plaintext = ("ATTACK AT DAWN THE ENEMY SHIPS WILL COME FROM THE NORTH AND SOUTH "
                     "THE RIVER CROSSING MUST BE COMPLETED BEFORE THE MORNING FOG LIFTS") * 2
        ciphertext = client.post("/classical/vigenere",
                                 json={"text": plaintext, "key": "LIME"}).json()["result"]

        body = client.get("/transposition/analysis/crack-vigenere",
                          params={"text": ciphertext, "max_key_length": 8}).json()
        assert body["results"][0]["key_length"] == 4
        assert body["results"][0]["key"] == "LIME"


class TestBlockEndpoints:
    @pytest.mark.parametrize("cipher_name", ["aes", "des"])
    @pytest.mark.parametrize("mode", ["ecb", "cbc", "ctr"])
    def test_round_trip(self, client, cipher_name, mode):
        # AES takes a 16-byte key, DES an 8-byte one; both are given in hex,
        # so the string lengths are 32 and 16 characters respectively.
        key = "00" * (16 if cipher_name == "aes" else 8)
        plaintext = "HALLO 2026"

        encrypted = client.post("/block/encrypt", json={
            "plaintext": plaintext, "key": key, "cipher": cipher_name, "mode": mode,
        }).json()

        decrypted = client.post("/block/decrypt", json={
            "ciphertext": encrypted["ciphertext"],
            "key": key,
            "iv": encrypted["iv"],
            "cipher": cipher_name,
            "mode": mode,
            "original_length": len(plaintext.encode("utf-8")),
        }).json()

        assert decrypted["plaintext"] == plaintext

    def test_cbc_generates_a_fresh_iv(self, client):
        payload = {"plaintext": "HELLO", "key": "00" * 16, "cipher": "aes", "mode": "cbc"}
        first = client.post("/block/encrypt", json=payload).json()
        second = client.post("/block/encrypt", json=payload).json()
        assert first["iv"] != second["iv"]
        assert first["ciphertext"] != second["ciphertext"]

    def test_ecb_needs_no_iv(self, client):
        body = client.post("/block/encrypt", json={
            "plaintext": "HELLO", "key": "00" * 16, "cipher": "aes", "mode": "ecb",
        }).json()
        assert body["iv"] is None

    def test_cbc_decrypt_requires_iv(self, client):
        encrypted = client.post("/block/encrypt", json={
            "plaintext": "HELLO", "key": "00" * 16, "cipher": "aes", "mode": "cbc",
        }).json()
        response = client.post("/block/decrypt", json={
            "ciphertext": encrypted["ciphertext"], "key": "00" * 16, "mode": "cbc",
        })
        assert response.status_code == 400
        assert "requires the IV" in response.json()["detail"]

    def test_invalid_hex_rejected(self, client):
        response = client.post("/block/encrypt", json={
            "plaintext": "HI", "key": "zz", "cipher": "aes", "mode": "cbc",
        })
        assert response.status_code == 400
        assert "hex" in response.json()["detail"]

    def test_unknown_cipher_rejected(self, client):
        response = client.post("/block/encrypt", json={
            "plaintext": "HI", "key": "00" * 16, "cipher": "blowfish", "mode": "cbc",
        })
        assert response.status_code == 422

    def test_mode_listing(self, client):
        modes = client.get("/block/modes").json()["modes"]
        assert {m["id"] for m in modes} == {"ecb", "cbc", "ctr"}
        assert all(m["summary"] for m in modes)


class TestHashEndpoints:
    def test_sha256(self, client):
        body = client.post("/hash/sha256", json={"message": "abc"}).json()
        assert body["digest"] == sha256("abc")
        assert body["algorithm"] == "SHA-256"

    def test_hmac_sha256(self, client):
        body = client.post("/hash/hmac-sha256",
                           json={"key": "key", "message": "The quick brown fox"}).json()
        assert body["digest"] == hmac_sha256(b"key", b"The quick brown fox").hex()


class TestRSAEndpoints:
    def test_full_cycle(self, client):
        keypair = client.post("/rsa/keygen", json={"bits": 512}).json()
        assert keypair["bits"] == 512
        assert keypair["private_key_hex"].count(":") == 4

        encrypted = client.post("/rsa/encrypt", json={
            "message": "HALLO 2026", "public_key": keypair["public_key_hex"],
        }).json()
        assert encrypted["block_count"] >= 1

        decrypted = client.post("/rsa/decrypt", json={
            "ciphertext": encrypted["ciphertext"],
            "private_key": keypair["private_key_hex"],
        }).json()
        assert decrypted["plaintext"] == "HALLO 2026"

    def test_wrong_private_key_gives_garbage(self, client):
        first = client.post("/rsa/keygen", json={"bits": 512}).json()
        second = client.post("/rsa/keygen", json={"bits": 512}).json()

        encrypted = client.post("/rsa/encrypt", json={
            "message": "SECRET", "public_key": first["public_key_hex"],
        }).json()

        decrypted = client.post("/rsa/decrypt", json={
            "ciphertext": encrypted["ciphertext"],
            "private_key": second["private_key_hex"],
        }).json()
        assert decrypted["plaintext"] != "SECRET"

    def test_keygen_rejects_odd_bits(self, client):
        # 511 passes schema validation but fails the library's even-size check,
        # which surfaces as a 400 rather than a 422.
        assert client.post("/rsa/keygen", json={"bits": 511}).status_code == 400

    def test_keygen_rejects_tiny_bits(self, client):
        assert client.post("/rsa/keygen", json={"bits": 128}).status_code == 422

    def test_encrypt_int(self, client):
        keypair = client.post("/rsa/keygen", json={"bits": 512}).json()
        body = client.post("/rsa/encrypt-int",
                           params={"message": 42, "public_key": keypair["public_key_hex"]}).json()
        assert int(body["ciphertext"], 16) < int(body["n"], 16)
        assert body["n_bits"] == 512


class TestDHRouters:
    def test_parameters(self, client):
        body = client.post("/dh/parameters", json={"bits": 256}).json()
        p = int(body["p"], 16)
        assert body["bits"] == 256
        assert (p - 1) % 2 == 0

    def test_rejects_tiny_parameters(self, client):
        assert client.post("/dh/parameters", json={"bits": 128}).status_code == 422

    def test_elgamal_cycle(self, client):
        params = client.post("/dh/parameters", json={"bits": 256}).json()
        keypair = client.post("/dh/elgamal/keygen", json={"p": params["p"], "g": params["g"]}).json()

        encrypted = client.post("/dh/elgamal/encrypt", json={
            "message": "ATTACK AT DAWN", "public": keypair["public"],
            "p": params["p"], "g": params["g"],
        }).json()
        assert encrypted["block_count"] >= 1

        decrypted = client.post("/dh/elgamal/decrypt", json={
            "c1": encrypted["c1"], "c2": encrypted["c2"], "lengths": encrypted["lengths"],
            "private": keypair["private"], "p": params["p"], "g": params["g"],
        }).json()
        # Spaces survive the round trip: the space is a symbol in the alphabet.
        assert decrypted["plaintext"] == "ATTACK AT DAWN"

    def test_exchange_rejects_degenerate_peer(self, client):
        params = client.post("/dh/parameters", json={"bits": 256}).json()
        # Scalars travel as strings; a degenerate peer value must still be
        # rejected rather than silently accepted.
        response = client.post("/dh/exchange", json={
            "private": "12345", "peer_public": "1",
            "p": params["p"], "g": str(params["g"]),
        })
        assert response.status_code == 400
        assert "peer public" in response.json()["detail"]


class TestECCRouters:
    def test_curve_listing(self, client):
        curves = client.get("/ecc/curves").json()["curves"]
        names = {c["name"] for c in curves}
        assert {"secp192r1", "secp256k1"} <= names

    def test_sign_verify_cycle(self, client):
        keys = client.post("/ecc/keygen", json={"curve": "secp192r1"}).json()
        # r and s are decimal strings: they exceed the JSON safe-integer range.
        assert isinstance(keys["private"], str)
        assert isinstance(keys["public"], str)

        signature = client.post("/ecc/sign", json={
            "message": "HELLO 2026", "private": keys["private"], "curve": "secp192r1",
        }).json()
        assert isinstance(signature["r"], str)
        assert isinstance(signature["s"], str)

        valid = client.post("/ecc/verify", json={
            "message": "HELLO 2026", "r": signature["r"], "s": signature["s"],
            "public": keys["public"], "curve": "secp192r1",
        }).json()
        assert valid["valid"] is True

    def test_verify_rejects_tampered_message(self, client):
        keys = client.post("/ecc/keygen", json={"curve": "secp192r1"}).json()
        signature = client.post("/ecc/sign", json={
            "message": "HELLO 2026", "private": keys["private"], "curve": "secp192r1",
        }).json()

        valid = client.post("/ecc/verify", json={
            "message": "TAMPERED", "r": signature["r"], "s": signature["s"],
            "public": keys["public"], "curve": "secp192r1",
        }).json()
        assert valid["valid"] is False

    def test_signature_survives_a_string_round_trip(self, client):
        # A 192-bit scalar has ~57 significant digits, well past what a JSON
        # number preserves. Assert the exact string comes back unchanged.
        keys = client.post("/ecc/keygen", json={"curve": "secp256k1"}).json()
        signature = client.post("/ecc/sign", json={
            "message": "PRECISION", "private": keys["private"], "curve": "secp256k1",
        }).json()

        again = client.post("/ecc/sign", json={
            "message": "PRECISION", "private": str(int(keys["private"])), "curve": "secp256k1",
        }).json()
        assert len(again["r"]) == len(signature["r"])

        valid = client.post("/ecc/verify", json={
            "message": "PRECISION", "r": again["r"], "s": again["s"],
            "public": keys["public"], "curve": "secp256k1",
        }).json()
        assert valid["valid"] is True

    def test_rejects_unknown_curve(self, client):
        assert client.post("/ecc/keygen", json={"curve": "curve25519"}).status_code == 400

    def test_rejects_point_off_curve(self, client):
        keys = client.post("/ecc/keygen", json={"curve": "secp192r1"}).json()
        response = client.post("/ecc/verify", json={
            "message": "HI", "r": "1", "s": "1", "public": "1,1", "curve": "secp192r1",
        })
        assert response.status_code == 400
        assert "does not lie on the curve" in response.json()["detail"]
