package ucs.model;

import java.io.IOException;
import java.util.ArrayList;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import ucs.control.SnifferControl;

/**
 * 
 * @author Alessandro A. Feitosa
 */
public class SnifferModel implements PacketReceiver {

	private SnifferControl snifferControl;
	private NetworkInterface[] dispositivos;// Lista dos dispositivos de rede
	private NetworkInterface dispositivoSelecionado;// Dispositivo selecionar para realizar a captura
	private int dispositivoIndex = 0;// Indice do dispositivo selecionar para realizar a captura
	private JpcapCaptor jpcap; //Biblioteca de captura
	private volatile ArrayList<Packet> listaDePacotes = new ArrayList<Packet>(); //Lista de pacotes capturados

	private PacketReceiver recebedorDePacotes;

	public SnifferModel(SnifferControl snifferControl) {
		super();
		this.snifferControl = snifferControl;
		this.recebedorDePacotes = this;
	}

	/**
	 * @decription Retorna todos os dispositivos de rede
	 * @return Lista com os dispositivos de rede
	 */
	public NetworkInterface[] getDevices() {
	    dispositivos = JpcapCaptor.getDeviceList(); // Lista de dispositivos
		return this.dispositivos;
	}

	/**
	 * @decription Abre a conexão
	 * @return dispositivo usados para conexão
	 */
	private NetworkInterface openDevice() throws IOException {
		//jpcap = JpcapCaptor.openFile("C:\\Users\\I848435\\Downloads\\http_amostra1");
		//jpcap = JpcapCaptor.openFile("C:\\Users\\I848435\\Downloads\\captura_ftp.pcap");
		
		jpcap = JpcapCaptor.openDevice (this.dispositivoSelecionado, 65535, true, 1000); // Abre a conexão e o dispositivo
		return dispositivoSelecionado;
	}

	/**
	 * @decription Prepare before capture: the closing of a jpcap, open a new
	 *             card to connect, Clear List
	 * @return
	 */
	public void beforeCapture() {
		// Para a captura atual
		if (this.jpcap != null) {
			this.jpcap.close();
			this.jpcap = null;
		}

		// Abre o dispositivo selecionado
		try {
			this.openDevice();
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Limpa a lista de pacotes
		this.listaDePacotes = new ArrayList<Packet>();
	}

	/**
	 * @decription Start capture
	 * @return
	 */
	public boolean startCapture() {
		this.jpcap.loopPacket(0, this.recebedorDePacotes);

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
	public Packet getPacketByIndex(int index) {
		if (index >= this.listaDePacotes.size() || index < 0)
		    return null;
		return this.listaDePacotes.get(index-1);
	}

	/**
	 * @decription PacketReceiver interface must implement the functions
	 *             implemented for processing the received packet
	 * @param packet
	 *            Packet capture
	 * @return
	 */
	public void receivePacket(Packet packet) {
		if (packet == null)// Não retorna nada em casa do pacote seja null
			return;
		synchronized (listaDePacotes) {
			addPacket(packet);
		}
	}

    public synchronized void addPacket(Packet packet) {
    	// Atualiza as estatisticas
    	this.jpcap.updateStat();
    	
    	if(packet instanceof IPPacket) {
    		// Novo pacote é adicionado à lista
    		this.listaDePacotes.add(packet);
    		// Atualiza a visualização dos pacotes
    		this.snifferControl.addNewPacket(this.listaDePacotes.size(), packet);
    	}
    }

	public int getDispositivoIndex() {
		return dispositivoIndex;
	}

	public void setDispositivoIndex(int dispositivoIndex) {
		this.dispositivoSelecionado = this.dispositivos[dispositivoIndex];
		this.dispositivoIndex = dispositivoIndex;
	}

	public ArrayList<Packet> getListaDePacotes() {
		return listaDePacotes;
	}
}
