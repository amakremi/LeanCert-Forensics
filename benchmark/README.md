# LeanCert locked benchmark

This package contains declarative development and held-out mutation definitions. It is
physically separate from the production validator. `freeze-benchmark` records immutable
digests; labels and mutation metadata are removed before validation and retained only in
the external mapping. Controlled perturbations are not natural forensic failures.
