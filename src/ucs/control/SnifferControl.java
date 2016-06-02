/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ucs.control;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

import javax.swing.DefaultComboBoxModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import jpcap.NetworkInterface;
import jpcap.packet.ARPPacket;
import jpcap.packet.DatalinkPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;
import cn.edu.shu.ipv6sniffer.model.Ipv6SnifferModel;

/**
 * 
 * @author Alessandro A. Feitosa
 */
public class SnifferControl {

	public static int totalPacket = 0;// O número total de pacotes

	private Ipv6SnifferModel ipv6SnifferModel = new Ipv6SnifferModel(this);// Camada de captura

	private javax.swing.JLabel ipv6Total;// Exibe o número total de ipv6
	private javax.swing.JLabel bytesTotal;// Usado para exibir o fluxo total
	private javax.swing.JLabel packetTotal;// Usado para exibir o fluxo total
	
	private javax.swing.JLabel totalTCP;// Usado para o total de pacotes TCP
	private javax.swing.JLabel totalUDP;// Usado para o total de pacotes UDP
	private javax.swing.JLabel totalHotOpt;// Usado para o total de pacotes Hop
	private javax.swing.JLabel totalIpv6Frag;// Usado para o total de pacotes IPv6 Frag.
	private javax.swing.JLabel totalIgmp;// Usado para o total de pacotes IGMP
	private javax.swing.JLabel totalIcmp6;// Usado para o total de pacotes ICMPv6
	private javax.swing.JLabel totalNoNxt;// Usado para o total de pacotes No next
	private javax.swing.JLabel totalOpts;// Usado para o total de pacotes Options
	private javax.swing.JLabel totalRoute;// Usado para o total de pacotes Route
	private javax.swing.JLabel totalUnknown;// Usado para o total de pacotes Unknown

	private javax.swing.JTree detailPacketTree;// Usado para listar detalhes do pacote
	private javax.swing.JComboBox<String> networkInterface;// Drop-down list para selecionar a placa de rede
	private javax.swing.JTable packetTable;// table para exposição dos pacotes
	private javax.swing.JButton startButton;// Usado para iniciar ou parar a captura
	private javax.swing.JButton statsButton;// Usado para exibir as estatisticas
	private javax.swing.JPanel totalPanel;// panel para totais
	private javax.swing.JTextArea textArea;// text area com informações dos pacotes

	private boolean startOrStop = false;
	private Thread captureThread = null;
	private TotalThread totalThread = null;
	private Object[] title = new Object[] { "Número", "Hora", "Origem", "Destino", "Protocolo" };

	private DefaultComboBoxModel<String> networkComboBoxModel = new DefaultComboBoxModel<String>();

	private volatile DefaultTableModel packetTableModel = new DefaultTableModel(title, 0);// O valor é usado para armazenar a tabela
	private DefaultTreeModel detailPacketTreeModel;

	/**
	 * @decription Inicia os componentes
	 */
	public void initAllComponents() {
		// TODO Auto-generated method stub
		this.networkInterface.setModel(networkComboBoxModel);
		NetworkInterface[] devices = this.ipv6SnifferModel.getDevices();
		for (NetworkInterface device : devices) {
			this.networkComboBoxModel.addElement(new String(device.description));
		}
		this.packetTable.setModel(packetTableModel);
		this.detailPacketTreeModel = new DefaultTreeModel(null);
		this.detailPacketTree.setModel(this.detailPacketTreeModel);
	}

	/**
	 * @decription Modelo de chamada é iniciado ou parado para realizar captura
	 * @return Inicio OK
	 */
	public boolean startOrStopCapture() {
		// Se ja foi iniciado, para o processo
		if (!this.startOrStop) {
			// iniciar a captura
			this.startCapture();
		} else {
			this.stopCapture();
		}
		startOrStop = !startOrStop;
		return true;
	}

	/**
	 * @decription Inicia a captura
	 */
	public void startCapture() {
		java.awt.EventQueue.invokeLater(new Runnable() {
			public void run() {
				// TODO Auto-generated method stub
				detailPacketTreeModel.setRoot(null);
				packetTableModel.setNumRows(0);
				networkInterface.setEnabled(false);
				// ipv6OnlyButton.setEnabled(false);
				startButton.setText("Parar");
			}
		});

		this.ipv6SnifferModel.setDeviceIndex(this.networkInterface
				.getSelectedIndex());

		// Captura multithreading
		this.captureThread = new Thread(new Runnable() {
			public void run() {
				// TODO Auto-generated method stub
				ipv6SnifferModel.beforeCapture();
				ipv6SnifferModel.resetTotal();
				ipv6SnifferModel.startCapture();
			}
		});

		this.totalThread = new TotalThread();

		this.captureThread.setDaemon(true);
		this.captureThread.start();
		this.totalThread.start();

		//this.startOrStop = true;
	}

	/**
	 * @decription Interrompe captura
	 */
	public void stopCapture() {
		this.ipv6SnifferModel.stopCapture();

		this.startButton.setEnabled(false);

		while (this.captureThread != null && this.captureThread.isAlive()) {
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		java.awt.EventQueue.invokeLater(new Runnable() {
			public void run() {
				networkInterface.setEnabled(true);
				// ipv6OnlyButton.setEnabled(true);
				startButton.setEnabled(true);
				startButton.setText("Start");
			}
		});

		this.totalThread.stopUpdate();
		//this.startOrStop = false;
	}

	/**
	 * @decription New package, update table
	 * @param index
	 * @param packet
	 */
	public synchronized void addNewPacket(int index, Packet packet) {
		synchronized (packetTableModel) {
			
			IPPacket ip = (IPPacket) packet;
			if(ip != null) {
				String sourceAddr = ip.src_ip.toString();
				String destAddr = ip.dst_ip.toString();
				this.packetTableModel.addRow(new Object[] { index,
						(new SimpleDateFormat("dd-MM-yyyy HH:mm:ss")).format(new Date()),
						sourceAddr.substring(1, sourceAddr.length()),
						destAddr.substring(1, destAddr.length()), getProtocolStr(ip.protocol) });
			}
			textArea.append(index + " - " +packet.toString() +"\n");
		}
	}

	/**
	 * @decription tcp refresh tree
	 * @param packet
	 *            Shows packages
	 */
	private DefaultMutableTreeNode tcpNode(TCPPacket tcp) {

		DefaultMutableTreeNode tcpNode = new DefaultMutableTreeNode(
				"Transmission Control Protocol");
		
		DefaultMutableTreeNode destNode = new DefaultMutableTreeNode(
				"Destination port：" + tcp.dst_port);
		DefaultMutableTreeNode srcNode = new DefaultMutableTreeNode(
				"Source Port：" + tcp.src_port);
		DefaultMutableTreeNode sequenceNode = new DefaultMutableTreeNode(
				"No：" + tcp.sequence);
		DefaultMutableTreeNode ack_numNode = new DefaultMutableTreeNode(
				"Confirmation Number：" + tcp.ack_num);
		DefaultMutableTreeNode urgNode = new DefaultMutableTreeNode(
				"URG Place：" + tcp.urg);
		DefaultMutableTreeNode ackNode = new DefaultMutableTreeNode(
				"ACK Place：：" + tcp.ack);
		DefaultMutableTreeNode pshNode = new DefaultMutableTreeNode(
				"PSH Place：：" + tcp.psh);
		DefaultMutableTreeNode rstNode = new DefaultMutableTreeNode(
				"RST Place：：" + tcp.rst);
		DefaultMutableTreeNode synNode = new DefaultMutableTreeNode(
				"SYN Place：：" + tcp.syn);
		DefaultMutableTreeNode finNode = new DefaultMutableTreeNode(
				"FIN Place：：" + tcp.fin);
		DefaultMutableTreeNode windowsNode = new DefaultMutableTreeNode(
				"Window：" + tcp.window);
		DefaultMutableTreeNode urgent_pointerNode = new DefaultMutableTreeNode(
				"Urgent Pointer：" + tcp.urgent_pointer);
		DefaultMutableTreeNode optionNode = new DefaultMutableTreeNode(
				"Options：" + tcp.option);
		tcpNode.add(destNode);
		tcpNode.add(srcNode);
		tcpNode.add(sequenceNode);
		tcpNode.add(ack_numNode);
		tcpNode.add(urgNode);
		tcpNode.add(ackNode);
		tcpNode.add(pshNode);
		tcpNode.add(rstNode);
		tcpNode.add(synNode);
		tcpNode.add(finNode);
		tcpNode.add(windowsNode);
		tcpNode.add(urgent_pointerNode);
		tcpNode.add(optionNode);
		
		return tcpNode;
	}

	/**
	 * @decription udp refresh tree
	 * @param packet
	 *            Shows packages
	 */
	private DefaultMutableTreeNode udpNode(UDPPacket udp) {
			
		DefaultMutableTreeNode udpNode = new DefaultMutableTreeNode(
				"User Datagram Protocol");
		
		DefaultMutableTreeNode destNode = new DefaultMutableTreeNode(
				"Destination port: " + udp.dst_port);
		DefaultMutableTreeNode lengthNode = new DefaultMutableTreeNode(
				"Packet length: " + udp.length);
		DefaultMutableTreeNode srcNode = new DefaultMutableTreeNode(
				"Source Port: " + udp.src_port);
		udpNode.add(destNode);
		udpNode.add(lengthNode);
		udpNode.add(srcNode);
		
		return udpNode;
	}

	/**
	 * @decription ipv6 node tree
	 * @param packet
	 *            Shows packages
	 */
	private DefaultMutableTreeNode ipv6Node(IPPacket ip) {
		
		DefaultMutableTreeNode ipNode = new DefaultMutableTreeNode(
				"Internet Protocol Version 6");

		// IP Version
		DefaultMutableTreeNode versionNode = new DefaultMutableTreeNode(
				"Version： " + ip.version);

		// Traffic class
		DefaultMutableTreeNode trafficClassNode = new DefaultMutableTreeNode(
				"Traffic class： " + ip.priority);

		// Flow label
		DefaultMutableTreeNode flowLabelNode = new DefaultMutableTreeNode(
				"Flow label： " + ip.flow_label);
		// payload length
		DefaultMutableTreeNode payloadLengthNode = new DefaultMutableTreeNode(
				"Payload length： " + ip.length);

		// The next header
		DefaultMutableTreeNode nextHeaderNode = new DefaultMutableTreeNode(
				"Next Header： " + this.getProtocolStr(ip.protocol));
		// Hops
		DefaultMutableTreeNode hoplimitNode = new DefaultMutableTreeNode(
				"Hop limit： " + ip.hop_limit);

		ipNode.add(versionNode);
		ipNode.add(trafficClassNode);
		ipNode.add(flowLabelNode);
		ipNode.add(payloadLengthNode);
		ipNode.add(nextHeaderNode);
		ipNode.add(hoplimitNode);

		// ip address
		DefaultMutableTreeNode srcNode = new DefaultMutableTreeNode(
				"Source IP address：" + ip.src_ip.getHostAddress());
		DefaultMutableTreeNode dstNode = new DefaultMutableTreeNode(
				"Destination IP Address：" + ip.dst_ip.getHostAddress());

		// Join ip junction
		ipNode.add(srcNode);
		ipNode.add(dstNode);

		return ipNode;
	}
	
	/**
	 * @decription ipv4 refresh tree
	 * @param packet
	 *            Shows packages
	 */
	private DefaultMutableTreeNode ipv4Node(IPPacket ip) {
		
		// IP Packets
		DefaultMutableTreeNode ipNode = new DefaultMutableTreeNode("Internet Protocol Version 4");
		// IP Version
		DefaultMutableTreeNode versionNode = new DefaultMutableTreeNode(
				"Version: " + ip.version);
		// Type of service
		DefaultMutableTreeNode tosNode = new DefaultMutableTreeNode(
				"Type of service: " + ip.rsv_tos);
		// Total length
		DefaultMutableTreeNode lengthNode = new DefaultMutableTreeNode(
				"Total length: " + ip.length);
		// Mark
		DefaultMutableTreeNode identNode = new DefaultMutableTreeNode(
				"Identification: " + ip.ident);
		// flags
		String flags = "0";
		String temp = "";
		if (ip.dont_frag) {
			flags = flags + "0";
			temp = temp + "Do not Fragment ";
		} else {
			flags = flags + "1";
			temp = temp + "Section ";
		}
		if (ip.more_frag) {
			flags = flags + "0";
			temp = temp + "Follow-up segment ";
		} else {
			flags = flags + "1";
			temp = temp + "No follow-up segment ";
		}
		flags = flags + " " + temp;
		// Flag
		DefaultMutableTreeNode flagsNode = new DefaultMutableTreeNode(
				"Flags:" + flags);

		// Fragment Offset
		DefaultMutableTreeNode offsetNode = new DefaultMutableTreeNode(
				"Fragment offset" + ip.offset);
		// Survival time
		DefaultMutableTreeNode hoplimitNode = new DefaultMutableTreeNode(
				"TTL:" + ip.hop_limit);

		// Upper layer protocol
		DefaultMutableTreeNode protocolNode = new DefaultMutableTreeNode("Protocol: " + getProtocolStr(ip.protocol)
				+ "(" + ip.protocol + ")");

		// Options
		DefaultMutableTreeNode optionNode = null;
		if (ip.option == null) {
			optionNode = new DefaultMutableTreeNode("Option: No");
		} else {
			optionNode = new DefaultMutableTreeNode("Option: "
					+ Arrays.toString(ip.option));
		}

		// Join ip junction
		ipNode.add(versionNode);
		ipNode.add(tosNode);
		ipNode.add(lengthNode);
		ipNode.add(identNode);
		ipNode.add(flagsNode);
		ipNode.add(offsetNode);
		ipNode.add(hoplimitNode);
		ipNode.add(protocolNode);
		ipNode.add(optionNode);

		// ip address
		DefaultMutableTreeNode srcNode = new DefaultMutableTreeNode("Source IP address: "
				+ ip.src_ip.getHostAddress());
		DefaultMutableTreeNode dstNode = new DefaultMutableTreeNode("Destination IP Address: "
				+ ip.dst_ip.getHostAddress());

		// Join ip junction
		ipNode.add(srcNode);
		ipNode.add(dstNode);

		return ipNode;
	}
	
	/**
	 * @decription ipv6 node tree
	 * @param packet
	 *            Shows packages
	 */
	private DefaultMutableTreeNode icmpv6Node(ICMPPacket ip) {
		
		if(ip == null)
			return null;
		
		DefaultMutableTreeNode icmpNode = new DefaultMutableTreeNode(
				"Internet Control Message Protocol v6");

		// Type
		DefaultMutableTreeNode typeNode = new DefaultMutableTreeNode(
				"Type： " + ip.type);
		icmpNode.add(typeNode);

		// Code
		DefaultMutableTreeNode codeNode = new DefaultMutableTreeNode(
				"Code：" + ip.code);
		icmpNode.add(codeNode);

		// Checksum
		DefaultMutableTreeNode checksumNode = new DefaultMutableTreeNode(
				"Checksum： " + ip.checksum);
		icmpNode.add(checksumNode);
		
		java.net.InetAddress[] routers=ip.router_ip;
		DefaultMutableTreeNode targetNode;
		for(int i=0; i<routers.length; i++) {
			// Target
			targetNode = new DefaultMutableTreeNode("Target address： " + routers[i]);
			icmpNode.add(targetNode);
      	}
		
		// Alive time
		DefaultMutableTreeNode aliveTimeNode = new DefaultMutableTreeNode(
				"Alive time： " + ip.alive_time);
		icmpNode.add(aliveTimeNode);
		
		// Advertised address
		DefaultMutableTreeNode advertisedAddressNode = new DefaultMutableTreeNode(
				"Advertised address： " + (int)ip.addr_num);
		icmpNode.add(advertisedAddressNode);

		// MTU of the packet is
		DefaultMutableTreeNode mtuNode = new DefaultMutableTreeNode(
				"MTU of the packet is： " + (int)ip.mtu);
		icmpNode.add(mtuNode);
		
		// Subnet mask 
		DefaultMutableTreeNode subnetNode = new DefaultMutableTreeNode(
				"Subnet mask ： " + (int)ip.subnetmask);
		icmpNode.add(subnetNode);

		return icmpNode;
	}
	
	/**
	 * @decription arp refresh tree
	 * @param packet
	 *            Shows packages
	 */
	private DefaultMutableTreeNode arpNode(ARPPacket arp) {
		
		DefaultMutableTreeNode arpNode = new DefaultMutableTreeNode(
				"ARP packets");

		// Various address
		DefaultMutableTreeNode senderMacAddrNode = new DefaultMutableTreeNode(
				"The sender MAC address：" + arp.getSenderHardwareAddress());
		String srcAddr = String.valueOf(arp.getSenderProtocolAddress());
		srcAddr = srcAddr.substring(1, srcAddr.length());
		DefaultMutableTreeNode senderProAddrNode = new DefaultMutableTreeNode(
				"Sender network addresses：" + srcAddr);

		DefaultMutableTreeNode targetMacAddrNode = new DefaultMutableTreeNode(
				"Destination MAC address：" + arp.getTargetHardwareAddress());
		String destAddr = String.valueOf(arp.getTargetProtocolAddress());
		destAddr = destAddr.substring(1, destAddr.length());
		DefaultMutableTreeNode targetProAddrNode = new DefaultMutableTreeNode(
				"Destination network address：" + destAddr);

		DefaultMutableTreeNode prototype = new DefaultMutableTreeNode(
				"Network layer protocol type："
						+ (arp.prototype == ARPPacket.PROTOTYPE_IP ? "IP"
								: "Unknown"));

		// ARP Type
		DefaultMutableTreeNode operation;
		if (arp.operation == ARPPacket.ARP_REQUEST)
			operation = new DefaultMutableTreeNode("ARP type: ARP request");
		else if (arp.operation == ARPPacket.ARP_REPLY)
			operation = new DefaultMutableTreeNode("ARP type: ARP reply");
		else
			operation = new DefaultMutableTreeNode("ARP Type: Unknown");

		// Data link frame type
		DefaultMutableTreeNode hardtype;
		if (arp.hardtype == ARPPacket.HARDTYPE_ETHER)
			hardtype = new DefaultMutableTreeNode(
					"Data Link Layer Type: Ethernet");
		else if (arp.hardtype == ARPPacket.HARDTYPE_FRAMERELAY)
			hardtype = new DefaultMutableTreeNode("Data Link Layer Type: FR");
		else if (arp.hardtype == ARPPacket.HARDTYPE_IEEE802)
			hardtype = new DefaultMutableTreeNode(
					"The data link layer type: IEEE802");
		else
			hardtype = new DefaultMutableTreeNode(
					"The data link layer types: Unknown");

		// Join ARP node
		arpNode.add(senderMacAddrNode);
		arpNode.add(senderProAddrNode);
		arpNode.add(targetMacAddrNode);
		arpNode.add(targetProAddrNode);
		arpNode.add(prototype);
		arpNode.add(operation);
		arpNode.add(hardtype);
		
		return arpNode;
	}

	/**
	 * @decription Refresh tree according to the selected table row
	 * @param selectedRow
	 *            Selected table row
	 */
	public void updateDetailPacketTree(int packetIndex) {
		// TODO Auto-generated method stub
		Packet packet = null;
		int rootNodes = 0;
		try {
			packet = this.ipv6SnifferModel.getPacketByIndex(packetIndex);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		DefaultMutableTreeNode root = new DefaultMutableTreeNode(
				"Packet");
		this.detailPacketTreeModel.setRoot(root);
		
		// Header data
		DefaultMutableTreeNode header = new DefaultMutableTreeNode(
				"Header data：" + Arrays.toString(packet.header));
		this.detailPacketTreeModel.insertNodeInto(header, root, rootNodes++);
		
		DatalinkPacket dp = packet.datalink;
		EthernetPacket etp = (EthernetPacket)dp;
		
		// Ethernet data
		DefaultMutableTreeNode ethernetNode = new DefaultMutableTreeNode("Ethernet");
		DefaultMutableTreeNode destEthernetNode = new DefaultMutableTreeNode(
				"Destination： " + etp.getDestinationAddress());
		ethernetNode.add(destEthernetNode);
		
		DefaultMutableTreeNode srcEthernetNode = new DefaultMutableTreeNode(
				"Source： " + etp.getSourceAddress());
		ethernetNode.add(srcEthernetNode);
		
		DefaultMutableTreeNode typeEthernetNode = new DefaultMutableTreeNode(
				"Type： " + getEthernetTypeStr(etp.frametype));
		ethernetNode.add(typeEthernetNode);
		
		this.detailPacketTreeModel.insertNodeInto(ethernetNode, root, rootNodes++);
		
		if(packet instanceof IPPacket) {
			IPPacket ip = (IPPacket)packet;
			// Choose Refresh tree type according to different protocols
			if(ip.version == 4) {
				this.detailPacketTreeModel.insertNodeInto(ipv4Node(ip), root, rootNodes++);
			} else if (ip.version == 6){
				this.detailPacketTreeModel.insertNodeInto(ipv6Node(ip), root, rootNodes++);
			}
			
			
			switch(ip.protocol) {
			case IPPacket.IPPROTO_ICMP:
				if(packet instanceof ICMPPacket)
					this.detailPacketTreeModel.insertNodeInto(icmpv6Node((ICMPPacket) packet), root, rootNodes++);
				break;
			case IPPacket.IPPROTO_IPv6:
				//ipv6Update(packet);// ipv6
				break;
			case IPPacket.IPPROTO_IPv6_ICMP:
				if(packet instanceof ICMPPacket)
					this.detailPacketTreeModel.insertNodeInto(icmpv6Node((ICMPPacket) packet), root, rootNodes++);
				break;
			case IPPacket.IPPROTO_TCP:
				if(packet instanceof TCPPacket)
					this.detailPacketTreeModel.insertNodeInto(tcpNode((TCPPacket) packet), root, rootNodes++);
				break;
			case IPPacket.IPPROTO_UDP:
				if(packet instanceof UDPPacket)
					this.detailPacketTreeModel.insertNodeInto(udpNode((UDPPacket) packet), root, rootNodes++);
				break;
			}
		} else if(packet instanceof ARPPacket) {
			this.detailPacketTreeModel.insertNodeInto(arpNode((ARPPacket) packet), root, rootNodes++);
		}
	}

	/**
	 * @decription Internal thread class, used to update the total information
	 * @author Alessandro A. Feitosa
	 * 
	 */
	class TotalThread extends Thread {

		private boolean update = true;

		@Override
		public void run() {
			// TODO Auto-generated method stub
			while (update) {
				totalTCP.setText("Total TCP: " + ipv6SnifferModel.getTcpTotal());
				totalUDP.setText("Total UDP: " + ipv6SnifferModel.getUdpTotal());
				totalHotOpt.setText("Total Hop: " + ipv6SnifferModel.getHopoptTotal());
				totalIpv6Frag.setText("Total IPv6 Frag.: " + ipv6SnifferModel.getIpv6FragTotal());
				totalIgmp.setText("Total IGMP: " + ipv6SnifferModel.getIgmpTotal());
				totalIcmp6.setText("Total ICMPv6: " + ipv6SnifferModel.getIcmp6Total());
				totalNoNxt.setText("Total No Next: " + ipv6SnifferModel.getNoNxtTotal());
				totalOpts.setText("Total Options: " + ipv6SnifferModel.getOptsTotal());
				totalRoute.setText("Total Route: " + ipv6SnifferModel.getRouteTotal());
				totalUnknown.setText("Total Unknown: " + ipv6SnifferModel.getUnknownTotal());
			}
		}

		public void stopUpdate() {
			this.update = false;
		}
	}

	public javax.swing.JLabel getIpv6Total() {
		return ipv6Total;
	}

	public void setIpv6Total(javax.swing.JLabel ipv6Total) {
		this.ipv6Total = ipv6Total;
	}

	public javax.swing.JLabel getBytesTotal() {
		return bytesTotal;
	}

	public void setBytesTotal(javax.swing.JLabel bytesTotal) {
		this.bytesTotal = bytesTotal;
	}

	public javax.swing.JLabel getPacketTotal() {
		return packetTotal;
	}

	public void setPacketTotal(javax.swing.JLabel packetTotal) {
		this.packetTotal = packetTotal;
	}

	public javax.swing.JTree getDetailPacketTree() {
		return detailPacketTree;
	}

	public void setDetailPacketTree(javax.swing.JTree detailPacketTree) {
		this.detailPacketTree = detailPacketTree;
	}

	public javax.swing.JComboBox<String> getNetworkInterface() {
		return networkInterface;
	}

	public void setNetworkInterface(
			javax.swing.JComboBox<String> networkInterface) {
		this.networkInterface = networkInterface;
		this.networkInterface.setModel(networkComboBoxModel);
	}

	public javax.swing.JTable getPacketTable() {
		return packetTable;
	}

	public void setPacketTable(javax.swing.JTable packetTable) {
		this.packetTable = packetTable;
	}

	public javax.swing.JButton getStartButton() {
		return startButton;
	}

	public void setStartButton(javax.swing.JButton startButton) {
		this.startButton = startButton;
	}

	public javax.swing.JPanel getTotalPanel() {
		return totalPanel;
	}

	public void setTotalPanel(javax.swing.JPanel totalPanel) {
		this.totalPanel = totalPanel;
	}
	
	public String getProtocolStr(Short protocol) {
		switch (protocol) {
		case IPPacket.IPPROTO_TCP:
			return "TCP";
		case IPPacket.IPPROTO_UDP:
			return "UDP";
		case IPPacket.IPPROTO_IGMP:
			return "IGMP";
		case IPPacket.IPPROTO_HOPOPT:
			return "IPv6 hop-by-hop";
		case IPPacket.IPPROTO_IP:
			return "IPv4";
		case IPPacket.IPPROTO_IPv6:
			return "IPv6";
		case IPPacket.IPPROTO_IPv6_Frag:
			return "IPv6 Fragment";
		case IPPacket.IPPROTO_IPv6_ICMP:
			return "ICMPv6";
		case IPPacket.IPPROTO_IPv6_NoNxt:
			return "NoNxt IPv6";
		case IPPacket.IPPROTO_IPv6_Opts:
			return "Dest IPv6";
		case IPPacket.IPPROTO_IPv6_Route:
			return "Routing IPv6";
		default:
			return "Unknown";
		}
	}
	
public String getEthernetTypeStr(Short protocol) {	
	switch (protocol) {
	case EthernetPacket.ETHERTYPE_ARP:
		return "ARP (" + protocol+")";
	case EthernetPacket.ETHERTYPE_IP:
		return "IP (" + protocol+")";
	case EthernetPacket.ETHERTYPE_IPV6:
		return "IPv6 (" + protocol+")";
	case EthernetPacket.ETHERTYPE_LOOPBACK:
		return "LoopBack (" + protocol+")";
	case EthernetPacket.ETHERTYPE_PUP:
		return "PUP (" + protocol+")";
	case EthernetPacket.ETHERTYPE_REVARP:
		return "Revarp (" + protocol+")";
	case EthernetPacket.ETHERTYPE_VLAN:
		return "Vlan (" + protocol+")";
	default:
		return "Unknown (" + protocol+")";
	}
}

public String getStatsCapture() {
	String stats = "Total bytes: " + ipv6SnifferModel.getBytesTotal() + "\n";
	stats += "Quantidade Total de Pacotes: " + ipv6SnifferModel.getPacketTotal() + "\n";
	stats += "\n============================\n";
	
	stats += "Quantidade Total de Pacotes TCP: " + ipv6SnifferModel.getTcpTotal() + "\n";
	stats += "Quantidade Total de Pacotes UDP: " + ipv6SnifferModel.getUdpTotal() + "\n";
	stats += "Quantidade Total de Pacotes ICMPv6: " + ipv6SnifferModel.getIcmp6Total() + "\n";
	
	return stats;
}

	public javax.swing.JLabel getTotalTCP() {
		return totalTCP;
	}

	public void setTotalTCP(javax.swing.JLabel totalTCP) {
		this.totalTCP = totalTCP;
	}

	public javax.swing.JLabel getTotalUDP() {
		return totalUDP;
	}

	public void setTotalUDP(javax.swing.JLabel totalUDP) {
		this.totalUDP = totalUDP;
	}

	public javax.swing.JLabel getTotalHotOpt() {
		return totalHotOpt;
	}

	public void setTotalHotOpt(javax.swing.JLabel totalHotOpt) {
		this.totalHotOpt = totalHotOpt;
	}

	public javax.swing.JLabel getTotalIpv6Frag() {
		return totalIpv6Frag;
	}

	public void setTotalIpv6Frag(javax.swing.JLabel totalIpv6Frag) {
		this.totalIpv6Frag = totalIpv6Frag;
	}

	public javax.swing.JLabel getTotalIgmp() {
		return totalIgmp;
	}

	public void setTotalIgmp(javax.swing.JLabel totalIgmp) {
		this.totalIgmp = totalIgmp;
	}

	public javax.swing.JLabel getTotalIcmp6() {
		return totalIcmp6;
	}

	public void setTotalIcmp6(javax.swing.JLabel totalIcmp6) {
		this.totalIcmp6 = totalIcmp6;
	}

	public javax.swing.JLabel getTotalNoNxt() {
		return totalNoNxt;
	}

	public void setTotalNoNxt(javax.swing.JLabel totalNoNxt) {
		this.totalNoNxt = totalNoNxt;
	}

	public javax.swing.JLabel getTotalOpts() {
		return totalOpts;
	}

	public void setTotalOpts(javax.swing.JLabel totalOpts) {
		this.totalOpts = totalOpts;
	}

	public javax.swing.JLabel getTotalRoute() {
		return totalRoute;
	}

	public void setTotalRoute(javax.swing.JLabel totalRoute) {
		this.totalRoute = totalRoute;
	}

	public javax.swing.JLabel getTotalUnknown() {
		return totalUnknown;
	}

	public void setTotalUnknown(javax.swing.JLabel totalUnknown) {
		this.totalUnknown = totalUnknown;
	}

	public TotalThread getTotalThread() {
		return totalThread;
	}

	public void setTotalThread(TotalThread totalThread) {
		this.totalThread = totalThread;
	}

	public javax.swing.JTextArea getTextArea() {
		return textArea;
	}

	public void setTextArea(javax.swing.JTextArea textArea) {
		this.textArea = textArea;
	}

	public javax.swing.JButton getStatsButton() {
		return statsButton;
	}

	public void setStatsButton(javax.swing.JButton statsButton) {
		this.statsButton = statsButton;
	}
}
