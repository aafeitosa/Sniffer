package ucs.view;

import java.awt.Component;
import java.awt.Dimension;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.TableCellRenderer;

import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import ucs.control.TcpControl;

public class Tcp extends JFrame
{
    /**
     * 
     */
    private static final long serialVersionUID = -8199824859551041193L;    
    private JTable table;
    private TcpControl tcpControl = new TcpControl();
    
    public Tcp(TCPPacket packet, List<Packet> listaDePacotes) {
        tcpControl.setListaDePacotes(listaDePacotes);
        setSize(new Dimension(1250, 800));
        setResizable(false);
        setLocationRelativeTo(null);
        setTitle("Conexão TCP");
        
        JPanel panel = new JPanel();
        panel.setPreferredSize(new Dimension(1250, 800));
        panel.setSize(new Dimension(1250, 800));
        panel.setBounds(1,1,1,1);
        getContentPane().add(panel);
        
        table = new JTable() {
            public TableCellRenderer getCellRenderer( int row, int column ) {
                return new CustomCellRenderer();
            }
        };
        
        table.setMaximumSize(new Dimension(1250, 700));
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setRowSelectionAllowed(false);
        table.setShowGrid(false);
        table.setRowHeight(35);
        
        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setPreferredSize(new Dimension(1250, 750));
        scrollPane.setMaximumSize(new Dimension(1250, 750));
        scrollPane.setSize(getSize());
        
        panel.add(scrollPane);
        
        tcpControl.setTable(table);
        tcpControl.setPacoteOrigem(packet);
        tcpControl.initTable();
        tcpControl.criaDiagrama();
        
    }
}
class CustomCellRenderer extends JPanel implements TableCellRenderer {
    
    public CustomCellRenderer() {
        super();
    }
    
    public Component getTableCellRendererComponent(
                        final JTable table, Object value,
                        boolean isSelected, boolean hasFocus,
                        int row, int column) {
        
        if(value instanceof JPanel) {
            this.add( (JPanel)value );
        } else if(value instanceof JProgressBar) {
            this.add( (JProgressBar)value );
        } else if(value instanceof ImageIcon) {
            this.add(new JLabel((ImageIcon)value));
        } else if(value instanceof JLabel) {
            this.add((JLabel)value);
        } else {
            this.add( new JLabel(value.toString()));
        }
        return this;
    }
}