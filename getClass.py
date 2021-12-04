# function to determine the class of an ipaddraddress
def findClass(ipaddr2):
    if 0 <= ipaddr2[0] <= 127:
        return "A"

    elif 128 <= ipaddr2[0] <= 191:
        return "B"

    elif 192 <= ipaddr2[0] <= 223:
        return "C"

    elif 224 <= ipaddr2[0] <= 239:
        return "D"

    else:
        return "E"


# function to separate network and host id from the given ipaddraddress
def seperate(ipaddr2, className):
    # for class A network
    if className == "A":
        print("Network Address is : ", ipaddr2[0])
        print("Host Address is : ", ".".join(ipaddr2[1:4]))

    # for class B network
    elif className == "B":
        print("Network Address is : ", ".".join(ipaddr2[0:2]))
        print("Host Address is : ", ".".join(ipaddr2[2:4]))

    # for class C network
    elif className == "C":
        print("Network Address is : ", ".".join(ipaddr2[0:3]))
        print("Host Address is : ", ipaddr2[3])

    else:
        print("In this Class, ipaddraddress is not divided into Network and Host ID")


# driver's code
 if __name__ == "__main__":
    ipaddr = "192.226.12.11"
    ipaddr = ipaddr.split(".")
    ipaddr = [int(i) for i in ipaddr]

#    getting the network class
    networkClass = findClass(ipaddr)
    print("Given ipaddraddress belongs to class : ", networkClass)

#    printing network and host id
    ipaddr = [str(i) for i in ipaddr]
    seperate(ipaddr, networkClass)
