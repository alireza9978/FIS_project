import timeit

import requests
from joblib import Parallel, delayed


def tcp_req(i):
    _ = requests.get(url="http://192.168.1.104:8000/login/")


start = timeit.default_timer()
result = Parallel(n_jobs=4)(delayed(tcp_req)(i) for i in range(12))
stop = timeit.default_timer()
print('Total Time: ', stop - start)
