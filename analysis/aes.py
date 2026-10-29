#!/usr/bin/env python3

from argparse import ArgumentParser
from enum import StrEnum
from pathlib import Path

import altair as alt
import polars as pl
from scipy.stats import f_oneway

class Operation(StrEnum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"

    @staticmethod
    def get_parser_args() -> dict:
        return {
            'type': Operation,
            'choices': Operation,
        }

    def get_process_name(self) -> str:
        match self:
            case Operation.ENCRYPT: return "encryption"
            case Operation.DECRYPT: return "decryption"

    def get_field_name(self) -> str:
        match self:
            case Operation.ENCRYPT: return "encryptionTime"
            case Operation.DECRYPT: return "decryptionTime"

    def get_throughput_field_name(self) -> str:
        match self:
            case Operation.ENCRYPT: return "encryptionThroughput"
            case Operation.DECRYPT: return "decryptionThroughput"

    def get_input_name(self) -> str:
        match self:
            case Operation.ENCRYPT: return "plaintext"
            case Operation.DECRYPT: return "ciphertext"


class ClockScaling:
    _clock_speed: int | None

    def __init__(self, clock_speed: int | None):
        self._clock_speed = clock_speed

    def get_unit(self):
        match self._clock_speed:
            case None: return "cycle"
            case int(_): return "second"

    def apply(self, df: pl.DataFrame, *columns: str) -> pl.DataFrame:
        match self._clock_speed:
            case None: return df
            case int(clock_speed):
                return df.with_columns(
                    pl.col(column) / clock_speed
                    for column in columns
                )

    def __repr__(self) -> str:
        return f"ClockScaling({self._clock_speed} -> {self.get_unit()})"

    @staticmethod
    def get_parser_args() -> dict:
        return {
            'type': int,
            'help': "Replace cycle measurements with seconds, given a clock speed in Hz",
            'type': lambda x: ClockScaling(int(x)),
            'default': ClockScaling(None)
        }


class Mode(StrEnum):
    CBC = "CBC"
    CTR = "CTR"
    GCM = "GCM"


KEY_SIZES = [128, 192, 256]


class Implementation:
    implementation: str
    mode: Mode
    misc: list[str]

    def __init__(self, name: str):
        split = name.split('.')

        library = split[0]

        match library:
            case "BearSSL":
                # BearSSL.<impl>.<mode>[.ghash]
                self.implementation = f"BearSSL.{split[1]}"
                self.mode = Mode(split[2])
                self.misc = split[3:]
            case "micro-AES":
                # micro-AES.<keySize>.<mode>
                self.implementation = f"micro-AES.{split[1]}"
                self.mode = Mode(split[2])
                self.misc = []
            case "mbedtls":
                # mbedtls.<mode>
                self.implementation = "mbedtls"
                self.mode = Mode(split[1])
                self.misc = []
            case unknown: raise ValueError(f"Unknown implementation {unknown}")

    def __repr__(self):
        return f"Implementation({self.implementation}, {self.mode}, {self.misc})"

    def __hash__(self):
        return hash((self.implementation, self.mode, *self.misc))

    def __eq__(self, other):
        if not isinstance(other, Implementation):
            return NotImplemented
        return all((
            self.implementation == other.implementation,
            self.mode == other.mode,
            self.misc == other.misc,
        ))


def plot_size_time(df: pl.DataFrame, key_size: int, mode: Mode, operation: Operation, clock_scaling: ClockScaling, out_path: Path):
    # Filter to requested results
    df = df.filter(
        pl.col("keySize") == key_size,
        [Implementation(impl).mode == mode for impl in df["implementation"]],
    )

    # Average timings across repetitions
    df = df.group_by(
        [
            pl.col('plaintextSize'),
            pl.col('plaintextId'),
            pl.col('keySize'),
            pl.col('keyId'),
            pl.col('ivId'),
            pl.col('implementation'),
        ],
        maintain_order=True,
    ).agg(
        pl.col(operation.get_field_name()).median(),
    )

    # Convert sizes to KB
    df = df.with_columns(pl.col("plaintextSize") / 1024)

    # Convert times to seconds if requested
    df = clock_scaling.apply(df, operation.get_field_name())

    (
        alt.Chart(df)
        .mark_line(point=True)
        .encode(
            x=alt.X(
                'plaintextSize',
                title=f"{operation.get_input_name().capitalize()} Size (KB)"
            ).scale(type='log'),
            y=alt.Y(
                operation.get_field_name(),
                title=f"{operation.get_process_name().capitalize()} Time ({clock_scaling.get_unit().capitalize()}s)"
            ).scale(type='log'),
            color='implementation',
        )
        .properties(title=f"Median {key_size}-bit {mode} {operation.get_process_name().capitalize()} Time")
        .save(out_path)
    )
    print("Saved to", out_path)


def plot_size_throughput(df: pl.DataFrame, key_size: int, mode: Mode, operation: Operation, clock_scaling: ClockScaling, out_path: Path):
    # Filter to requested results
    df = df.filter(
        pl.col("keySize") == key_size,
        [Implementation(impl).mode == mode for impl in df["implementation"]],
    )

    # Average timings across repetitions
    df = df.group_by(
        [
            pl.col('plaintextSize'),
            pl.col('plaintextId'),
            pl.col('keySize'),
            pl.col('keyId'),
            pl.col('ivId'),
            pl.col('implementation'),
        ],
        maintain_order=True,
    ).agg(
        pl.col(operation.get_field_name()).median(),
    )

    # Convert sizes to KB
    df = df.with_columns(pl.col("plaintextSize") / 1024)

    # Convert times to seconds if requested
    df = clock_scaling.apply(df, operation.get_field_name())

    # Calculate throughput
    df = df.with_columns(
        (pl.col('plaintextSize') / pl.col(operation.get_field_name())).alias(operation.get_throughput_field_name()),
    )

    (
        alt.Chart(df).mark_line(point=True)
        .encode(
            x=alt.X(
                'plaintextSize',
                title=f"{operation.get_input_name().capitalize()} Size (KB)"
            ).scale(type='log'),
            y=alt.Y(
                operation.get_throughput_field_name(),
                title=f"{operation.get_process_name().capitalize()} Throughput (KB/{clock_scaling.get_unit().capitalize()})"
            ),
            color='implementation',
        )
        .properties(title=f"Median {key_size}-bit {mode} {operation.get_process_name().capitalize()} Throughput")
        .save(out_path)
    )
    print("Saved to", out_path)


def test_ct(df: pl.DataFrame, key_size: int, mode: Mode, operation: Operation, secret: str, out_path: Path):
    # Filter to requested results
    df = df.filter(
        pl.col("keySize") == key_size,
        [Implementation(impl).mode == mode for impl in df["implementation"]],
    )

    # Only consider largest plaintexts
    print(f"Analysing {key_size}-bit {mode} {operation.get_process_name()} results at largest plaintext size {df['plaintextSize'].max()/1024} KB for constant-time over secret {secret}")
    df = df.filter(
        pl.col('plaintextSize') == pl.col('plaintextSize').max()
    )

    # Calculate degrees of freedom
    k = len(df.unique(secret))
    N = k * len(df.unique('repetition'))

    with out_path.open('w') as out:
        out.write(f"implementation\tF({k-1},{N-k})\tp\n")
        for impl, impl_df in df.partition_by('implementation', as_dict=True).items():
            # Check full data is present for each implementation
            impl_k = len(impl_df.unique(secret))
            impl_N = impl_k * len(impl_df.unique('repetition'))
            assert impl_k == k
            assert impl_N == N

            # ANOVA between secret values
            f, p = f_oneway(*[
                p.select(operation.get_field_name())
                for p in impl_df.partition_by(secret)
            ])

            out.write(f"{impl[0]}\t{f[0]:.2f}\t{p[0]:.3f}\n")
    print("Saved to", out_path)


def main():
    parser = ArgumentParser(description="AES results analysis")
    parser.add_argument("in_path", type=Path, help="Results TSV path")
    subparsers = parser.add_subparsers(dest="command", required=True)

    sp_time = subparsers.add_parser("plot_size_time", help="Plot time against plaintext size")
    sp_time.add_argument("operation", **Operation.get_parser_args())
    sp_time.add_argument("key_size", type=int, choices=KEY_SIZES)
    sp_time.add_argument("mode", type=Mode, choices=Mode)
    sp_time.add_argument("out_path", type=Path)
    sp_time.add_argument("--scale-to-clock", **ClockScaling.get_parser_args())

    sp_throughput = subparsers.add_parser("plot_size_throughput", help="Plot throughput against plaintext size")
    sp_throughput.add_argument("operation", **Operation.get_parser_args())
    sp_throughput.add_argument("key_size", type=int, choices=KEY_SIZES)
    sp_throughput.add_argument("mode", type=Mode, choices=Mode)
    sp_throughput.add_argument("out_path", type=Path)
    sp_throughput.add_argument("--scale-to-clock", **ClockScaling.get_parser_args())

    sp_ct_plaintext = subparsers.add_parser("test_ct", help="Test the correlation between plaintext/key values and encryption/decryption times")
    sp_ct_plaintext.add_argument("operation", **Operation.get_parser_args())
    sp_ct_plaintext.add_argument("key_size", type=int, choices=KEY_SIZES)
    sp_ct_plaintext.add_argument("mode", type=Mode, choices=Mode)
    sp_ct_plaintext.add_argument("secret", type=str, choices=['plaintext', 'key'])
    sp_ct_plaintext.add_argument("out_path", type=Path)

    args = parser.parse_args()

    results: pl.DataFrame = pl.read_csv(args.in_path, separator='\t')

    # Currently assumed to be results from a single board
    board = results["#board"][0]
    assert results.select(pl.col('#board') == board)['#board'].all()
    results.drop_in_place("#board")

    match args.command:
        case "plot_size_time":
            plot_size_time(results, args.key_size, args.mode, args.operation, args.scale_to_clock, args.out_path)
        case "plot_size_throughput":
            plot_size_throughput(results, args.key_size, args.mode, args.operation, args.scale_to_clock, args.out_path)
        case "test_ct":
            test_ct(results, args.key_size, args.mode, args.operation, args.secret + 'Id', args.out_path)

if __name__ == '__main__':
    main()
