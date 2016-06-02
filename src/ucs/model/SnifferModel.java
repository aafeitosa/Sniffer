package ucs.model;

import java.io.IOException;
import java.util.ArrayList;

import cn.edu.shu.ipv6sniffer.control.Ipv6SnifferControl;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.ARPPacket;
import jpcap.packet.DatalinkPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;

/**
 * 
 * @author Alessandro A. Feitosa
 */
public class SnifferModel implements PacketReceiver {

	private SnifferControl ipv6SnifferControl;
	private NetworkInterface[] devices;// Store all cards
	private NetworkInterface device;// Card you want to monitor
	private int deviceIndex = 0;// Monitoring the corresponding index card
	private JpcapCaptor jpcap;
	private volatile ArrayList<Packet> packetList = new ArrayList<Packet>(100);

	private PacketReceiver packetReceiver;

	
	private volatile long bytesTotal = 0;// Total traffic
	private volatile int packetTotal = 0;// The total number of packets
	
	private volatile int ipv6Total = 0;	
	private volatile int ipv4Total = 0;
	
	//Protocol Totals
	private volatile int tcpTotal = 0;
	private volatile int udpTotal = 0;
	private volatile int hopoptTotal = 0;
	private volatile int ipv6FragTotal = 0;
	private volatile int igmpTotal = 0;
	private volatile int icmp6Total = 0;
	private volatile int noNxtTotal = 0;
	private volatile int optsTotal = 0;
	private volatile int routeTotal = 0;
	private volatile int unknownTotal = 0;
	
	//Ethernet Totals
	private volatile int addressTypeIP = 0;
	private volatile int addressTypeARP = 0;
	private volatile int addressTypeREVARP = 0;
	private volatile int addressTypeVLAN = 0;
	private volatile int addressTypeIPV6 = 0;
	private volatile int addressTypeLOOPBACK = 0;

	public SnifferModel(SnifferControl ipv6SnifferControl) {
		super();
		this.ipv6SnifferControl = ipv6SnifferControl;
		this.packetReceiver = this;
		// TODO Auto-generated constructor stub
	}

	/**
	 * @decription Get all of the cards
	 * @return A list of all network cards
	 */
	public NetworkInterface[] getDevices() {
		devices = JpcapCaptor.getDeviceList(); // List of devices
		return this.devices;
	}

	/**
	 * @decription Open connection
	 * @return The use of the card
	 */
	private NetworkInterface openDevice() throws IOException {
		
		//jpcap = JpcapCaptor.openFile("C:\\Users\\officeworks\\Downloads\\v6.pcap");
		//jpcap = JpcapCaptor.openFile("C:\\Users\\officeworks\\Downloads\\icmp.pcap");
		
		jpcap = JpcapCaptor.openDevice(this.device, 65535, true, 10000); // Open connections and equipment 
		jpcap.setFilter("src host fe:80:0:0", true);
		// Listen only IP packets
		//jpcap.setFilter("ip", true); // Listen only IP data packet
		return device;
	}

	/**
	 * @decription Prepare before capture: the closing of a jpcap, open a new
	 *             card to connect, Clear List
	 * @return
	 */
	public void beforeCapture() {
		// Turn off the original captor
		if (this.jpcap != null) {
			this.jpcap.close();
			this.jpcap = null;
		}

		// Open a new device
		try {
			this.openDevice();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Empty the package list packages
		this.packetList = new ArrayList<Packet>(100);
	}

	/**
	 * @decription Start capture
	 * @return
	 */
	public boolean startCapture() {
		this.jpcap.loopPacket(161, this.packetReceiver);

		return true;
	}

	/**
	 * @decription Stop Ethereal
	 * @return
	 */
	public boolean stopCapture() {
		this.jpcap.breakLoop();
		this.jpcap.close();
		return true;
	}

	/**
	 * @decription Get the package through the serial number
	 * @param index
	 *            Pacote No.
	 * @return
	 * @throws Exception
	 */
	public Packet getPacketByIndex(int index) throws Exception {
		if (index >= this.packetList.size() || index < 0)
			throw new Exception(
					"Packet sequence number is greater than the number of packets");
		return this.packetList.get(index);
	}

	/**
	 * @decription Statistics is set to 0
	 */
	public void resetTotal() {
		tcpTotal = 0;
		udpTotal = 0;
		bytesTotal = 0;
		packetTotal = 0;
		ipv6Total = 0;
		hopoptTotal = 0;
		ipv6FragTotal = 0;
		icmp6Total = 0;
		noNxtTotal = 0;
		optsTotal = 0;
		routeTotal = 0;
		unknownTotal = 0;
		igmpTotal = 0;
		ipv4Total = 0;
	}

	/**
	 * @decription PacketReceiver interface must implement the functions
	 *             implemented for processing the received packet
	 * @param packet
	 *            Packet capture
	 * @return
	 */
	public void receivePacket(Packet packet) {
		// TODO Auto-generated method stub
		if (packet == null)// No package, return
			return;
		//Filter only ipv6
		if (((IPPacket)packet).version != 6)
			return;
		synchronized (packetList) {
			addPacket(packet);
		}
	}

public synchronized void addPacket(Packet packet) {
	// Update statistics
	this.jpcap.updateStat();
	this.bytesTotal += packet.len;
	this.packetTotal++;
	
	IPPacket ip = (IPPacket) packet;
	
	if (ip != null) {
		
		if (ip.version == 6) {
			this.ipv6Total++;// ipv6 Package
		} else if(ip.version == 6) {
			this.ipv4Total++;// ipv6 Package
		}

		switch (ip.protocol) {
		case IPPacket.IPPROTO_TCP:
			this.tcpTotal++;
			break;
		case IPPacket.IPPROTO_UDP:
			this.udpTotal++;
			break;
		case IPPacket.IPPROTO_HOPOPT:
			this.hopoptTotal++;
			break;
		case IPPacket.IPPROTO_ICMP:
			this.icmp6Total++;
			break;
		case IPPacket.IPPROTO_IGMP:
			this.igmpTotal++;
			break;
		case IPPacket.IPPROTO_IP:
			this.ipv4Total++;
			break;
		case IPPacket.IPPROTO_IPv6:
			this.ipv6Total++;
			break;
		case IPPacket.IPPROTO_IPv6_Frag:
			this.ipv6FragTotal++;
			break;
		case IPPacket.IPPROTO_IPv6_ICMP:
			this.icmp6Total++;
			break;
		case IPPacket.IPPROTO_IPv6_NoNxt:
			this.noNxtTotal++;
			break;
		case IPPacket.IPPROTO_IPv6_Opts:
			this.optsTotal++;
			break;
		case IPPacket.IPPROTO_IPv6_Route:
			this.routeTotal++;
			break;
		}
		
		DatalinkPacket dp = ip.datalink;
		EthernetPacket ept=(EthernetPacket)dp;
		
		
		switch (ept.frametype) {
		case EthernetPacket.ETHERTYPE_ARP:
			this.addressTypeARP++;
			break;
		case EthernetPacket.ETHERTYPE_IP:
			this.addressTypeIP++;
			break;
		case EthernetPacket.ETHERTYPE_IPV6:
			this.addressTypeIPV6++;
			break;
		case EthernetPacket.ETHERTYPE_LOOPBACK:
			this.addressTypeLOOPBACK++;
			break;
		case EthernetPacket.ETHERTYPE_PUP:
			this.addressTypeREVARP++;
			break;
		case EthernetPacket.ETHERTYPE_REVARP:
			this.addressTypeREVARP++;
			break;
		case EthernetPacket.ETHERTYPE_VLAN:
			this.addressTypeVLAN++;
			break;
		}
		
		// The new packages added to the list
		this.packetList.add(packet);
		// Refresh view layer forms
		this.ipv6SnifferControl.addNewPacket(this.packetList.size() - 1, packet);
	}
}

	public int getDeviceIndex() {
		return deviceIndex;
	}

	public void setDeviceIndex(int deviceIndex) {
		this.device = this.devices[deviceIndex];
		this.deviceIndex = deviceIndex;
	}

	public ArrayList<Packet> getPacketList() {
		return packetList;
	}

	public long getBytesTotal() {
		return bytesTotal;
	}

	public void setBytesTotal(long bytesTotal) {
		this.bytesTotal = bytesTotal;
	}

	public int getPacketTotal() {
		return packetTotal;
	}

	public void setPacketTotal(int packetTotal) {
		this.packetTotal = packetTotal;
	}

	public int getIpv6Total() {
		return ipv6Total;
	}

	public void setIpv6Total(int ipv6Total) {
		this.ipv6Total = ipv6Total;
	}

	public int getTcpTotal() {
		return tcpTotal;
	}

	public void setTcpTotal(int tcpTotal) {
		this.tcpTotal = tcpTotal;
	}

	public int getUdpTotal() {
		return udpTotal;
	}

	public void setUdpTotal(int udpTotal) {
		this.udpTotal = udpTotal;
	}

	public int getHopoptTotal() {
		return hopoptTotal;
	}

	public void setHopoptTotal(int hopoptTotal) {
		this.hopoptTotal = hopoptTotal;
	}

	public int getIpv6FragTotal() {
		return ipv6FragTotal;
	}

	public void setIpv6FragTotal(int ipv6FragTotal) {
		this.ipv6FragTotal = ipv6FragTotal;
	}

	public int getIcmp6Total() {
		return icmp6Total;
	}

	public void setIcmp6Total(int icmp6Total) {
		this.icmp6Total = icmp6Total;
	}

	public int getNoNxtTotal() {
		return noNxtTotal;
	}

	public void setNoNxtTotal(int noNxtTotal) {
		this.noNxtTotal = noNxtTotal;
	}

	public int getOptsTotal() {
		return optsTotal;
	}

	public void setOptsTotal(int optsTotal) {
		this.optsTotal = optsTotal;
	}

	public int getRouteTotal() {
		return routeTotal;
	}

	public void setRouteTotal(int routeTotal) {
		this.routeTotal = routeTotal;
	}

	public int getUnknownTotal() {
		return unknownTotal;
	}

	public void setUnknownTotal(int unknownTotal) {
		this.unknownTotal = unknownTotal;
	}

	public int getIgmpTotal() {
		return igmpTotal;
	}

	public void setIgmpTotal(int igmpTotal) {
		this.igmpTotal = igmpTotal;
	}

	public int getIpv4Total() {
		return ipv4Total;
	}

	public void setIpv4Total(int ipv4Total) {
		this.ipv4Total = ipv4Total;
	}
}
