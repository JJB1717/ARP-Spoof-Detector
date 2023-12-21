import tkinter as tk
from tkinter import ttk
import threading
from scapy.all import *

class ARP_Spoof_Detection_GUI:
    def __init__(self, master):
        self.master = master
        master.title("ARP Spoof Detection")
        
        master.configure(bg="#222")

        
        input_frame = tk.Frame(master, pady=10, bg="#222")
        input_frame.pack()

        
        ip_lab = tk.Label(input_frame, text="IP Address:", font=("Arial", 14), bg="#222", fg="white")
        ip_lab.grid(row=0, column=0, padx=5, pady=5)
        self.ip_entry = tk.Entry(input_frame, font=("Arial", 14), width=15)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)

        mac_label = tk.Label(input_frame, text="MAC Address:", font=("Arial", 14), bg="#222", fg="white")
        mac_label.grid(row=1, column=0, padx=5, pady=5)
        self.mac_entry = tk.Entry(input_frame, font=("Arial", 14), width=15)
        self.mac_entry.grid(row=1, column=1, padx=5, pady=5)

        
        self.button = ttk.Button(input_frame, text="Start Detection", style='my.TButton', command=self.start_detection)
        self.button.grid(row=2, column=0, columnspan=2, pady=10)

        
        result_frame = tk.Frame(master, bg="#222")
        result_frame.pack()

        
        self.result_label = tk.Label(result_frame, text="", font=("Arial", 14), bg="#222", fg="white")
        self.result_label.pack(pady=10)
        self.result_label_2 = tk.Label(result_frame, text="", font=("Arial", 14), bg="#222", fg="white")
        self.result_label_2.pack(pady=20)

    def start_detection(self):
        self.button.config(state="disabled")
        self.result_label.config(text=" [+] Scanning for ARP spoofing [+] ", fg="gray")

        ip_address = self.ip_entry.get()
        mac_address = self.mac_entry.get()

        detection_thread = threading.Thread(target=self.detect_arp_spoofing, args=(ip_address, mac_address))
        detection_thread.start()

    def detect_arp_spoofing(self, ip_address, mac_address):
        arp_req = ARP(pdst=ip_address)
        brdcst = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_req_brdcst = brdcst/arp_req
        result = srp(arp_req_brdcst, timeout=3, verbose=0)[0]

        detected_macs = set()

        for sent_packet, rec_pac in result:
            if rec_pac[ARP].hwsrc != mac_address:
                detected_macs.add(rec_pac[ARP].hwsrc)
        
       

        if detected_macs:
            attack_IP = self.getIP(str(detected_macs))
            self.result_label.config(text=" [+] ARP Spoofing Detected [+] \n Spoofed MAC addresses: {}".format(", ".join(detected_macs)), fg="red")
            self.result_label_2.config(text="Attacker IP : {}".format(attack_IP),fg="red")
        else:
            self.result_label.config(text=" [+] No ARP spoofing detected [+] ", fg="green")

        self.button.config(state="normal")

    def getIP(self,tar_mac):
        print(" \n In GET_IP --> target mac = ",tar_mac," --> type =  ",type(tar_mac),"\n")
        arp=ARP(op=1,pdst='192.168.205.0/24',hwdst='ff:ff:ff:ff:ff:ff',psrc='192.168.205.1')
        ether=Ether(dst='ff:ff:ff:ff:ff:ff')
        packet=ether/arp
        result=srp(packet,timeout=3,verbose=0)[0]
        for sent,rec in result:
        
            ip=rec.psrc
            mac=rec.hwsrc
            if mac==tar_mac and rec.psrc != '192.168.205.139' :
                return ip


style = ttk.Style()
style.configure('my.TButton', font=("Arial", 14), background="#2eb8b8", foreground="white")
style.configure('my.TLabel', font=("Arial", 14), background="black", foreground="white")
root = tk.Tk()
root.configure(bg="black")
gui = ARP_Spoof_Detection_GUI(root)
root.mainloop()