import numpy as np
import pandas as pd

df = pd.read_csv("ir.csv", header=None)
df["mask"] = np.array(32 - np.log2(df[2].to_numpy())).astype(np.int32).astype(str)
df["ip"] = df[0].astype(str)
df = df[["ip", "mask"]]
df.to_csv("iran_ip.csv", index=None)
