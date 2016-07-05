package ucs.control;

import java.awt.Color;
import java.awt.GridLayout;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

public class TcpControl
{
    private List<Packet> listaDePacotes;
    private TCPPacket pacoteOrigem;
    
    private JTable table;
    private JProgressBar barCliente = new JProgressBar();
    private JProgressBar barServidor = new JProgressBar();
    private JPanel panelCliente = new JPanel();
    private JLabel labelCliente = new JLabel();
    private JPanel panelServidor = new JPanel();
    private JLabel labelServidor = new JLabel();
    private GridLayout progressLayout = new GridLayout(2,1);
    private JLabel labelSequencia;
    
    private List<Long> listaSeqCliente = new ArrayList<Long>();
    private List<Long> listaSeqServidor = new ArrayList<Long>();
    private String origemSelecionado;
    private String destinoSelecionado;
    private String ipCliente = null;
    private int maxJanelaCliente = 0;
    private String ipServidor = null;
    private int maxJanelaServidor = 0;
    
    private Object[] title = new Object[] { "Num. Sequencia", "Num. Reconhecimento", "", "Cliente", "", "Servidor", "", "SYN", "FIN", "RST", "ACK", "Tamanho TCP Seg." };
    private volatile DefaultTableModel tableModel = new DefaultTableModel(title, 0);
    
    public void initTable() {        
        
        table.setModel(tableModel);
        table.getColumnModel().getColumn(0).setPreferredWidth(100);
        table.getColumnModel().getColumn(1).setPreferredWidth(100);
        table.getColumnModel().getColumn(2).setPreferredWidth(200);
        table.getColumnModel().getColumn(3).setPreferredWidth(150);
        table.getColumnModel().getColumn(4).setPreferredWidth(50);
        table.getColumnModel().getColumn(5).setPreferredWidth(150);
        table.getColumnModel().getColumn(6).setPreferredWidth(200);
        table.getColumnModel().getColumn(7).setPreferredWidth(40);
        table.getColumnModel().getColumn(7).setPreferredWidth(40);
        table.getColumnModel().getColumn(8).setPreferredWidth(40);
        table.getColumnModel().getColumn(9).setPreferredWidth(40);
        table.getColumnModel().getColumn(10).setPreferredWidth(40);
        table.getColumnModel().getColumn(11).setPreferredWidth(100);
        
    }
    /*
     * Método que define quem é cliente e servidor baseado nas flags SYN and ACK 
     *
     */
    public void setClienteAndServidor() {
        for (Packet packet : listaDePacotes) { //for para definir quem é cliente e quem é servidor
            if(packet instanceof TCPPacket) {
                TCPPacket tcpPacket = (TCPPacket)packet;
                if(((getIpAndPorta(tcpPacket.src_ip, tcpPacket.src_port).equals(origemSelecionado)) || 
                   (getIpAndPorta(tcpPacket.src_ip, tcpPacket.src_port).equals(destinoSelecionado))) &&
                    tcpPacket.syn && !tcpPacket.ack) { //Se o pacote tem flags SYN e não tem ACK, ele é o cliente
                    
                    ipCliente = getIpAndPorta(tcpPacket.src_ip, tcpPacket.src_port);
                    ipServidor = getIpAndPorta(tcpPacket.dst_ip, tcpPacket.dst_port);
                    break;
                }
            }
        }
        
        //Se não encontrar o inicio da conexão, utiliza o pacote de origem
        if(ipCliente == null) {
            ipCliente = origemSelecionado;
        }
        
        if(ipServidor == null) {
            ipServidor = destinoSelecionado;
        }
    }
    
    /*
     * Método que define o tamanho máximo da janela do cliente e servidor baseado nas amostras
     */
    public void setTamanhoJanelaMax(){
        for (Packet packet : listaDePacotes) { //For para pegar o tamanho máximo da janela do cliente e servidor
            if(packet instanceof TCPPacket) {
                TCPPacket tcpPacket = (TCPPacket)packet;
                if (getIpAndPorta(tcpPacket.src_ip, tcpPacket.src_port).equals(ipCliente)) {
                    if(tcpPacket.window > maxJanelaCliente) {
                        maxJanelaCliente = tcpPacket.window;
                    }
                } else if (getIpAndPorta(tcpPacket.src_ip, tcpPacket.src_port).equals(ipServidor)) {
                    if(tcpPacket.window > maxJanelaServidor) {
                        maxJanelaServidor = tcpPacket.window;
                    }
                }
            }
        }
        
        barCliente.setMaximum(maxJanelaCliente);
        barCliente.setValue(0);
        barServidor.setMaximum(maxJanelaServidor);
        barServidor.setValue(0);
    }
    public void criaDiagrama() {
        
        //Salva o ip + porta e origem do pacote selecionado
        origemSelecionado = getIpAndPorta(pacoteOrigem.src_ip, pacoteOrigem.src_port);  
        
        //Salva o ip + porta de destino do pacote selecionado
        destinoSelecionado = getIpAndPorta(pacoteOrigem.dst_ip, pacoteOrigem.dst_port); 
        
        setClienteAndServidor();
        setTamanhoJanelaMax();
        
        for (Packet packet : listaDePacotes) {
            if(packet instanceof TCPPacket) {
                TCPPacket tcpPacket = (TCPPacket)packet;
                
                String origem = getIpAndPorta(tcpPacket.src_ip, tcpPacket.src_port);
                String destino = getIpAndPorta(tcpPacket.dst_ip, tcpPacket.dst_port);
                
                if((origem.equals(ipCliente) && destino.equals(ipServidor)) ||
                        (origem.equals(ipServidor) && destino.equals(ipCliente))) {
                    
                    ImageIcon direcao;
                    if(origem.equals(ipCliente)) {
                        direcao = new ImageIcon("right.png");
                        
                        panelCliente = new JPanel();
                        labelCliente = new JLabel(maxJanelaCliente - tcpPacket.window + " de " + maxJanelaCliente); 
                        
                        barCliente = new JProgressBar();
                        barCliente.setMaximum(maxJanelaCliente);
                        barCliente.setValue(maxJanelaCliente - tcpPacket.window);
                        
                        panelCliente.setLayout(progressLayout);
                        panelCliente.add(barCliente);
                        panelCliente.add(labelCliente);
                        
                        labelSequencia = new JLabel(String.valueOf(tcpPacket.sequence));
                        labelSequencia.setForeground(Color.BLACK);
                        
                        if(tcpPacket.data.length > 0) { //Só adiciona a sequence se o pacote tiver algum dado.
                            if(listaSeqCliente.contains(Long.valueOf(tcpPacket.sequence))) { //Verifica se o num. de sequencia está repetido
                                labelSequencia.setForeground(Color.RED);
                            } else {
                                listaSeqCliente.add(tcpPacket.sequence);
                            }
                        }
                                                
                    } else {
                        direcao = new ImageIcon("left.png");
                        
                        panelServidor = new JPanel();
                        labelServidor = new JLabel(maxJanelaServidor - tcpPacket.window + " de " + maxJanelaServidor);
                        
                        barServidor = new JProgressBar();
                        barServidor.setMaximum(maxJanelaServidor);
                        barServidor.setValue(maxJanelaServidor - tcpPacket.window);
                        
                        panelServidor.setLayout(progressLayout);
                        panelServidor.add(barServidor);
                        panelServidor.add(labelServidor);
                        
                        labelSequencia = new JLabel(String.valueOf(tcpPacket.sequence));
                        labelSequencia.setForeground(Color.BLACK);
                        
                        if(tcpPacket.data.length > 0) { //Só adiciona a sequence se o pacote tiver algum dado.
                            if(listaSeqServidor.contains(Long.valueOf(tcpPacket.sequence))) { //Verifica se o num. de sequencia está repetido
                                labelSequencia.setForeground(Color.RED);
                            } else {
                                listaSeqServidor.add(tcpPacket.sequence);
                            }
                        }
                    }
                    
                    this.tableModel.addRow(new Object[] { labelSequencia, //JLabel com o número de sequencia
                            tcpPacket.ack_num,  //número de reconhecimento
                            panelCliente, // progress bar do controle de fluxo do cliente
                            ipCliente, //ip do cliente
                            direcao,  //sentido do pacote
                            ipServidor,  //ip do servidor
                            panelServidor,  // progress bar do controle de fluxo do servidor 
                            tcpPacket.syn ? 1:0, //flag SYN
                            tcpPacket.fin ? 1:0, //flag FIN
                            tcpPacket.rst ? 1:0, //flag RST
                            tcpPacket.ack ? 1:0, //flag ACK
                            tcpPacket.data.length }); //tamanho do pacote
                }
            }
        }
    }
    
    private String getIpAndPorta(InetAddress ip, int porta) {
        return ip.toString().substring(1, ip.toString().length()) + " : " + porta;
    }

    public void setListaDePacotes(List<Packet> listaDePacotes)
    {
        this.listaDePacotes = listaDePacotes;
    }

    public JTable getTable()
    {
        return table;
    }

    public void setTable(JTable table)
    {
        this.table = table;
    }

    public List<Packet> getListaDePacotes()
    {
        return listaDePacotes;
    }

    public TCPPacket getPacoteOrigem()
    {
        return pacoteOrigem;
    }

    public void setPacoteOrigem(TCPPacket pacoteOrigem)
    {
        this.pacoteOrigem = pacoteOrigem;
    }
}
