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
import ucs.model.SnifferModel;
import ucs.view.Tcp;

/**
 * 
 * @author Alessandro A. Feitosa
 */
public class SnifferControl {

	private SnifferModel ipv6SnifferModel = new SnifferModel(this);// Camada de captura

	private javax.swing.JTree detailPacketTree;// Usado para listar detalhes do pacote
	private javax.swing.JComboBox<String> networkInterface;// Drop-down list para selecionar a placa de rede
	private javax.swing.JTable packetTable;// table para exposição dos pacotes
	private javax.swing.JButton startButton;// Usado para iniciar ou parar a captura
	private javax.swing.JPanel totalPanel;// panel para totais

	private boolean startOrStop = false;
	private Thread captureThread = null;
	private Object[] title = new Object[] { "Número", "Hora", "Origem", "Destino", "Próx. Cabeçalho" };

	private DefaultComboBoxModel<String> networkComboBoxModel = new DefaultComboBoxModel<String>();

	private volatile DefaultTableModel packetTableModel = new DefaultTableModel(title, 0);// O valor é usado para armazenar a tabela
	private DefaultTreeModel detailPacketTreeModel;

	/**
	 * @decription Inicia os componentes
	 */
	public void initAllComponents() {
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
			    try {
    				detailPacketTreeModel.setRoot(null);
    				packetTableModel.setNumRows(0);
    				networkInterface.setEnabled(false);
			    } catch(Exception e) {
			        
			    }
				startButton.setText("Parar");
			}
		});

		this.ipv6SnifferModel.setDispositivoIndex(this.networkInterface
				.getSelectedIndex());

		// Captura multithreading
		this.captureThread = new Thread(new Runnable() {
			public void run() {
				ipv6SnifferModel.beforeCapture();
				ipv6SnifferModel.startCapture();
			}
		});

		this.captureThread.setDaemon(true);
		this.captureThread.start();
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
				e.printStackTrace();
			}
		}

		java.awt.EventQueue.invokeLater(new Runnable() {
			public void run() {
				networkInterface.setEnabled(true);
				startButton.setEnabled(true);
				startButton.setText("Start");
			}
		});
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
    
    public void abrirPacote() {
        Object selected = this.packetTable.getModel().getValueAt(
                this.packetTable.getSelectedRow(), 0);
        if(selected != null) {
        
            Packet packet = ipv6SnifferModel.getPacketByIndex(Integer
                    .valueOf(this.packetTable.getModel().getValueAt(
                            this.packetTable.getSelectedRow(), 0) + ""));
            
            if(packet instanceof TCPPacket) {
                new Tcp((TCPPacket)packet, ipv6SnifferModel.getListaDePacotes()).setVisible(true);
            }
        }
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
}
