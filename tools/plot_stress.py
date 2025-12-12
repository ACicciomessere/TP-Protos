import csv
import matplotlib.pyplot as plt

conns = []
throughput = []

with open("stress_results.csv", newline="") as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        conns.append(int(row["conns"]))
        throughput.append(float(row["throughput_MBps"]))

plt.figure()
plt.plot(conns, throughput, marker="o")
plt.xlabel("Conexiones simultáneas (c)")
plt.ylabel("Throughput (MB/s)")
plt.title("Rendimiento del servidor SOCKS5 bajo carga concurrente")
plt.grid(True)

plt.tight_layout()
plt.savefig("stress_results.png", dpi=150)
# Si querés ver el gráfico en pantalla también:
# plt.show()
