import os


def main():
    results = []
    cbmc_file = "cbmc_model.cpp"
    temporal_file = "tmp.txt"

    for key_length in range(1, 38):
        print(f"Trying key length: {key_length}")

        try:
            os.system(
                f'cbmc --unwind 100 -DKEY_LENGTH_FIXED={key_length} --trace {cbmc_file} | grep -i "flag=" > {temporal_file}'
            )

            with open(temporal_file, "r") as f:
                line = f.readline()

            flag = line.split("{")[1].split("}")[0].split(",")
            flag = "".join(chr(int(x, 10)) for x in flag)
            results.append([key_length, flag])
        except Exception as e:
            print(f"Error: {e}")

    print("=" * 70)
    for r in results:
        print(f"Flag found with key length {r[0]}: {r[1]}")

    try:
        os.remove(temporal_file)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
