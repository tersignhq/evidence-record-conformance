// Cross-implementation measurement: recompute the suite's pinned digests with the
// TypeScript stack (viem) and compare byte-for-byte against the Python verifier.
// Run from any directory with viem installed:  node tools/cross_check_ts.mjs
import { keccak256, concatHex, numberToHex, stringToHex } from "viem";

const pins = [
  ["keccak256(empty)", keccak256("0x"),
   "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"],
  ["keccak256('abc')", keccak256(stringToHex("abc")),
   "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"],
  ["digestOf({b:'x',a:1})", keccak256(stringToHex('{"a":1,"b":"x"}')),
   "0x84fc3d9faf736ddfdb9baab9973656bd8d9bd142f1dfff8aa513a774fddfdd04"],
  ["digestOf integer-key vector", keccak256(stringToHex('{"1":"c","10":"a","2":"b"}')),
   "0x426b770f81b8ad5e307bcfb767deb02f8d32cd340d81a946be88bb184857e81b"],
  ["chainLink(genesis, null, 1)",
   keccak256(concatHex([
     "0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4",
     `0x${"0".repeat(64)}`,
     numberToHex(1, { size: 8 }),
   ])),
   "0x837c2d85db422b59f89527ef33bfe862af7230895635b63141b09cde169187a5"],
];

let bad = 0;
for (const [name, got, want] of pins) {
  const ok = got === want;
  if (!ok) bad++;
  console.log(`${ok ? "MATCH " : "DIVERGE"} ${name}: ${got}`);
}
process.exit(bad === 0 ? 0 : 1);
