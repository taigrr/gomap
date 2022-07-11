package main

func main() {

	//str, _ := gomap.GetLocalIP()
	//fmt.Println(str)

}

//func main() {

//		mgmtInterface, err := net.InterfaceByName("wlp5s0")
//		if err != nil {
//			fmt.Println("Unable to find interface")
//			os.Exit(-1)
//		}
//
//		addrs, err := mgmtInterface.Addrs()
//		if err != nil {
//			fmt.Println("Interface has no address")
//			os.Exit(-1)
//		}
//		for _, addr := range addrs {
//			var ip net.IP
//			var mask net.IPMask
//			switch v := addr.(type) {
//			case *net.IPNet:
//				ip = v.IP
//				mask = v.Mask
//			case *net.IPAddr:
//				ip = v.IP
//				mask = ip.DefaultMask()
//			}
//			if ip == nil {
//				continue
//			}
//			ip = ip.To4()
//			if ip == nil {
//				continue
//			}
//			cleanMask := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
//			fmt.Println(ip, cleanMask)
//		}
// }
