# The Qualcomm PBL short-signature flaw

Ryan ([@oscardagrach](https://github.com/oscardagrach)) · October 2026

## Summary

The primary boot loader (PBL) on Qualcomm SoCs is mask ROM on the die. It is the
first code the application processor runs, it is the root of the secure boot
chain, and **it cannot be patched or updated on any part that shipped with it.**

The PBL verifies images with RSA PKCS#1 v1.5. It takes the length of the
signature from the image's own header, which is attacker controlled, and uses it
without requiring that it match the length of the public key's modulus.

If any certificate in the chain uses public exponent **e = 3**, an attacker can
compute a valid-looking signature for an arbitrary image in microseconds, with no
private key, and have the PBL accept it on a device with secure boot fused on.

## What the PBL verifies

Two things, and both are worth having:

1. **SBL1**, read from the boot device at every power-on. Forging it is
   persistent and gives control of the whole chain below.
2. **The Sahara programmer**, downloaded over USB when the SoC comes up in
   emergency download mode (EDL, USB `05c6:9008`). Forging it gives arbitrary
   code execution at the earliest possible stage, over a cable, on a locked
   device.

Both go through the same routine, so one flaw covers both.

## How the verification is supposed to work

Every Qualcomm boot image is an MBN: a small header, then code, then a
signature, then an X.509 certificate chain. The header declares where each piece
is and how long it is.

The PBL:

1. Parses the certificate chain and hashes the root, comparing it against the OEM
   public key hash burned into QFPROM.
2. Reads `SW_ID` and `HW_ID` out of the leaf certificate's subject OU fields and
   checks them against the image's declared software ID and the SoC's hardware
   ID, so a signature for one image cannot be replayed onto another.
3. Computes a keyed digest over the image. Note it signs the **bare digest**,
   with no DigestInfo wrapper:

   ```
   D1 = SHA256(header || code)
   D2 = SHA256((SW_ID XOR 0x36 repeated) || D1)
   D3 = SHA256((HW_ID XOR 0x5c repeated) || D2)

   EM = 00 01 FF FF ... FF 00 || D3
   ```

4. Raises the signature to the public exponent, `s^e mod n`, and compares the
   result against `EM`.

## The bug

Step 4 uses the signature length from the header. A correct implementation
requires that length to equal the modulus length, because an RSA signature is by
definition the same width as the modulus. The PBL does not check it, and it also
sizes the expected `EM` block from the same header-supplied value.

So an attacker can declare a signature of, say, 48 bytes against a 256-byte
modulus, and the PBL will do a 48-byte comparison.

## Why e = 3 makes that fatal

Declare a signature of `L` bytes and treat `s` as an `L`-byte integer. The PBL
computes `s^3 mod n`. If `s^3 < n`, **the modular reduction never happens** and
the result is the exact integer cube of `s`. The PBL then compares only `L` bytes
of it against the expected block.

So the attacker needs an integer `s` with:

```
s^3  ==  EM   (mod 2^(8L))        and        s^3 < n
```

Cube roots modulo a power of two are not hard. You lift the solution one bit at a
time, testing each bit against the target, which is a few hundred iterations of
cheap arithmetic. There is no factoring and no private key involved. For a
2048-bit modulus, an `L` of 44 to 72 bytes leaves `s^3` comfortably under `n`.

Four practical constraints:

- **The leaf must be e = 3.** With e = 65537, `s^65537` exceeds `n` for any
  useful `s`, the reduction happens, and the attacker loses all control of the
  result.
- **The digest must be odd**, or no cube root exists modulo a power of two. Since
  the digest covers the header, which contains the signature length, you simply
  try successive values of `L` until one yields an odd digest.
- **`L` must leave at least eight `0xFF` padding bytes**, the PKCS#1 minimum,
  which for SHA-256 means `L` of about 44 or more.
- **The certificate chain must still be genuine** and must root to the fused OEM
  hash, with a leaf whose `SW_ID` and `HW_ID` match the image and the SoC. The
  attacker does not forge the chain; they reuse a real one. Shipped firmware is
  full of them, including older releases for the same device, and a chain only
  has to be found once per image type.

The attack reduces to: find an OEM-signed chain with an e = 3 leaf and the right
IDs, then compute a short cube-root signature for whatever image you want.

## Why it cannot be fixed

The PBL is mask ROM. There is no update path, no fuse that changes the routine,
and no firmware release that replaces it. Every unit of an affected SoC has the
same boot ROM for the life of the silicon.

The same verification routine is duplicated in the stages below the PBL, and
those copies were corrected at some point, since they live in flash. That does
not rescue the PBL, and it does not fully close the hole either: the PBL will
still accept a forged SBL1, and a forged SBL1 is just a file, so whoever can boot
one can also strip its signature checks before booting it. The downstream fixes
harden the **stock** chain; they do not protect a device whose first link accepts
short signatures.

On affected parts the practical bar is therefore not "can secure boot be
bypassed" but "can the attacker get an image in front of the PBL" - which EDL
mode answers over a USB cable.

## Indications of vendor awareness

I have no advisory or statement to point to, so what follows is inference rather
than fact. But two changes visible in shipped firmware are difficult to read as
anything other than a response to this, which suggests Qualcomm has been aware of
it for a long time.

**The downstream copies were fixed.** The same verification routine exists in
SBL1 and in TrustZone, both of which live in flash. Firmware from roughly 2016
onwards generally carries the corrected form: it requires the signature length to
equal the modulus length, and it sizes the expected block from the modulus rather
than from the image header. Nothing can be done about the boot ROM's copy, so
correcting the two software copies would be the whole available response - which
is consistent with someone having looked at this routine and fixed what they
could reach.

**The signing keys were rotated away from e = 3.** This is the more telling
indicator, and it is directly observable by anyone with two firmware releases for
the same device. Comparing an earlier release against a later one:

| image | leaf public exponent |
|---|---|
| SBL1, 2015 release | **e = 3** |
| SBL1, 2017 release | e = 65537 |
| aboot, 2015 release | **e = 3** |
| aboot, 2017 release | e = 65537 |

Moving every leaf to e = 65537 makes a short-signature forgery infeasible no
matter what the boot ROM does, because the cube-root trick depends entirely on
the small exponent. That is precisely the mitigation recommended below. Key
rotation is not something that happens by accident, and e = 3 has no advantage
here worth keeping, so the change at least looks deliberate - though a general
move away from low exponents, for reasons unrelated to this, would explain it
equally well.

The practical consequence for anyone assessing an affected device: the exposure
is not uniform across the SoC's lifetime. A unit running current firmware is hard
to attack this way, because its chains use e = 65537. A unit running an old
release, or an attacker willing to use an **old release's certificate chain**, is
a different matter - which is why anti-rollback fuses are the part of the
mitigation that actually does work.

## Affected range

Confirmed first-hand, by disassembling the boot ROMs:

| target | state |
|---|---|
| APQ8064 PBL | vulnerable |
| APQ8084 PBL | vulnerable |
| MSM8974 PBL | vulnerable |

A mask ROM is identical on every unit of that SoC forever, so "vulnerable" here
is a permanent property of the silicon rather than of a firmware build.

## What a correct implementation does

Either of these alone defeats the attack:

1. **Require `signature_len == modulus_len`.** A short signature is rejected
   outright.
2. **Size the expected block from the modulus**, not from the header. With the
   scan bound set by the key, a short `s` produces a cube whose middle and upper
   words are garbage, and the padding check fails.

Having both is defence in depth, and worth it: a verifier that checked only the
equality but still sized its padding scan from the header would be back to square
one if that check were ever bypassed.

## Guidance

- **Do not use e = 3 anywhere in a boot chain.** This is the single change that
  makes the whole class infeasible on parts with a vulnerable PBL, and it costs
  nothing. e = 65537 is fine. The PBL cannot be fixed, but what it is asked to
  verify is entirely under the OEM's control.
- **Treat every length in an image header as attacker controlled**, including the
  ones that look structural.
- **Anti-rollback fuses matter here**, because the attack depends on reusing
  genuine old certificate chains. A monotonic version fuse that refuses chains
  below the current version limits which chains remain usable.
- **Guard write access to the boot partitions as if it were secure boot itself.**
  On an affected part, the ability to write SBL1 is equivalent to a full bypass.
- **Treat EDL as an attack surface, not a service tool.** It is a path to the
  vulnerable verifier that needs no disassembly and no exploit beyond this one.
