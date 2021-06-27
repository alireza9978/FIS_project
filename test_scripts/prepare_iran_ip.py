import pandas as pd
import numpy as np

df = pd.read_csv("ir.csv", header=None)
df["mask"] = np.array(32 - np.log2(df[2].to_numpy())).astype(np.int32)
df["final_ip"] = df[0] + '\\' + df['mask'].astype(str)
df = df[["final_ip"]]
df.to_csv("iran_ip.csv", index=None, header=None)