package ucs.model;

import java.io.IOException;
import java.util.ArrayList;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.DatalinkPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import ucs.control.SnifferControl;

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
	private volatile ArrayList<Packet> packetList = new ArrayList<Packet>();

	private PacketReceiver packetReceiver;

	public SnifferModel(SnifferControl ipv6SnifferControl) {
		super();
		this.ipv6SnifferControl = ipv6SnifferControl;
		this.packetReceiver = this;
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
		
		jpcap = JpcapCaptor.openDevice(this.device, 65535, true, 1000); // Open connections and equipment 
		//jpcap.setFilter("src host fe:80:0:0", true);
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
		/*if (((IPPacket)packet).version != 6)
			return;*/
		synchronized (packetList) {
			addPacket(packet);
		}
	}

    public synchronized void addPacket(Packet packet) {
    	// Update statistics
    	this.jpcap.updateStat();
    	
    	IPPacket ip = (IPPacket) packet;
    	
    	if (ip != null) {
    		
    		DatalinkPacket dp = ip.datalink;
    		EthernetPacket ept=(EthernetPacket)dp;
    		
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
}
