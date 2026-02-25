# Prevajanje javanske vmesne kode v zbirni jezik RISC V

V tem repozitoriju je izvorna koda prevajalnika iz javanske vmesne kode v zbirni jezik RISC-V, ki smo ga implementirali v okviru diplomske naloge.

## Namestitev

Predpostavljamo, da je [Rust](https://rust-lang.org/) naložen.

```
$ git clone https://github.com/Karim632/diploma
$ cd diploma
$ cargo build
```

## Uporaba

Prevajalnik pričakuje datoteko `Test.class` v vrhnjem direktoriju od repozitorija. Ta datoteka naj bo rezultat prevajanja z `javac`.
```
$ cargo run
```

## Testiranje

### Namestitev orodij

Za testiranje potrebujemo [RISC-V GNU Compiler Toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain), [Spike RISC-V ISA Simulator](https://github.com/riscv-software-src/riscv-isa-sim) in [RISC-V Proxy Kernel](https://github.com/riscv-software-src/riscv-pk).

Za namestitev teh orodij sledimo navodilom v povezavah. Ker je prevajalnik namenjen 32-bitni RISC-V arhitekturi, moramo pred namestitvijo RISC-V GNU Compiler Toolchain in RISC-V Proxy Kernel to določiti pri konfiguraciji.

RISC-V GNU Compiler Toolchain:
```
$ ./configure --prefix=$RISCV --with-arch=rv32imf_zicsr --with-abi=ilp32f
```

RISC-V Proxy Kernel (predpostavljamo, da je trenutni delovni direktorij /build/, kot v uradnih navodilih):
```
$ ../configure --prefix=$RISCV --host=riscv32-unknown-elf --with-arch=rv32imfd_zicsr_zifencei --with-abi=ilp32f
```

### Zagon

Če imamo rezultat prevajanja v datoteki `out.s`:
```
$ riscv32-unknown-elf-gcc -o test out.s
$ spike --isa=rv32imfd $RISCV/riscv32-unknown-elf/bin/pk test
```

Za pregled nad registri in pomnilnikom med izvajanjem lahko uporabimo razhroščevalnik, ki ga ponuja Spike:
```
$ spike --isa=rv32imfd -d $RISCV/riscv32-unknown-elf/bin/pk test
```
