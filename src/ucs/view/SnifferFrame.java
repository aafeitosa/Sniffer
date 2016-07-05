package ucs.view;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.SwingConstants;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import ucs.control.SnifferControl;

/**
 *
 * @author Alessandro A. Feitosa
 */
public class SnifferFrame extends javax.swing.JFrame {

	/**
	 * 
	 */
	private static final long serialVersionUID = -7160835837632290482L;
	public static JFrame frame = new JFrame("Interactive Frame");
	private SnifferControl ipv6SnifferControl = new SnifferControl();

    private javax.swing.JTree detailPacketTree;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JComboBox<String> networkInterface;
    private javax.swing.JTable packetTable;
    private javax.swing.JButton startButton;
    private javax.swing.JButton btnAbrirPacote;
    
    /**
     * @param args
     *            the command line arguments
     */
    public static void main(String args[]) {
        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new SnifferFrame().setVisible(true);
                frame.setExtendedState(JFrame.MAXIMIZED_BOTH);
            }
        });
    }

	/**
	 * Creates new form Ipv6SnifferFrame
	 */
	public SnifferFrame() {
	    setTitle("Sniffer Redes II");
		initComponents();
		ipv6SnifferControl.setDetailPacketTree(detailPacketTree);
		ipv6SnifferControl.setNetworkInterface(networkInterface);
		ipv6SnifferControl.setPacketTable(packetTable);
		ipv6SnifferControl.setStartButton(startButton);

		ipv6SnifferControl.initAllComponents();
	}

	private void initComponents() {

		jPanel1 = new javax.swing.JPanel();
		jScrollPane1 = new javax.swing.JScrollPane();
		packetTable = new javax.swing.JTable();
		jScrollPane2 = new javax.swing.JScrollPane();
		detailPacketTree = new javax.swing.JTree();

		setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

		packetTable.setModel(new javax.swing.table.DefaultTableModel() {
			private static final long serialVersionUID = 616040251973729541L;
			boolean[] canEdit = new boolean[] { false, false, false, false };

			public boolean isCellEditable(int rowIndex, int columnIndex) {
				return canEdit[columnIndex];
			}
		});
		packetTable.getSelectionModel().addListSelectionListener(
				new ListSelectionListener() {
					public void valueChanged(ListSelectionEvent e) {
						tableSelectActionPerformed(e);
					}
				});
		jScrollPane1.setViewportView(packetTable);

		jScrollPane2.setViewportView(detailPacketTree);
		
		JPanel panel = new JPanel();
		
		btnAbrirPacote = new JButton("Abrir Pacote");
		btnAbrirPacote.setEnabled(false);
		btnAbrirPacote.addActionListener(new ActionListener() {
		    public void actionPerformed(ActionEvent e) {
		        ipv6SnifferControl.abrirPacote();
		    }
		});
		
		javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(
				jPanel1);
		jPanel1Layout.setHorizontalGroup(
		    jPanel1Layout.createParallelGroup(Alignment.TRAILING)
		        .addGroup(jPanel1Layout.createSequentialGroup()
		            .addContainerGap()
		            .addGroup(jPanel1Layout.createParallelGroup(Alignment.LEADING)
		                .addGroup(jPanel1Layout.createSequentialGroup()
		                    .addGroup(jPanel1Layout.createParallelGroup(Alignment.TRAILING)
		                        .addComponent(panel, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 651, Short.MAX_VALUE)
		                        .addComponent(jScrollPane1, GroupLayout.DEFAULT_SIZE, 651, Short.MAX_VALUE)
		                        .addComponent(jScrollPane2, GroupLayout.DEFAULT_SIZE, 651, Short.MAX_VALUE))
		                    .addGap(25))
		                .addGroup(jPanel1Layout.createSequentialGroup()
		                    .addComponent(btnAbrirPacote)
		                    .addContainerGap(587, Short.MAX_VALUE))))
		);
		jPanel1Layout.setVerticalGroup(
		    jPanel1Layout.createParallelGroup(Alignment.LEADING)
		        .addGroup(jPanel1Layout.createSequentialGroup()
		            .addContainerGap()
		            .addComponent(panel, GroupLayout.PREFERRED_SIZE, 36, GroupLayout.PREFERRED_SIZE)
		            .addPreferredGap(ComponentPlacement.RELATED)
		            .addComponent(jScrollPane1, GroupLayout.DEFAULT_SIZE, 189, Short.MAX_VALUE)
		            .addGap(18)
		            .addComponent(jScrollPane2, GroupLayout.DEFAULT_SIZE, 227, Short.MAX_VALUE)
		            .addGap(59)
		            .addComponent(btnAbrirPacote)
		            .addContainerGap())
		);
		panel.setLayout(null);
		jLabel1 = new javax.swing.JLabel();
		jLabel1.setBounds(10, 9, 229, 14);
		panel.add(jLabel1);
		
		jLabel1.setHorizontalAlignment(SwingConstants.LEFT);
		jLabel1.setText("Selecione um adaptador de rede para monitorar");
		networkInterface = new javax.swing.JComboBox<String>();
		networkInterface.setBounds(249, 6, 241, 20);
		panel.add(networkInterface);
				
		networkInterface.setModel(new javax.swing.DefaultComboBoxModel<String>());
		
		startButton = new javax.swing.JButton();
		startButton.setBounds(496, 5, 114, 23);
		startButton.setContentAreaFilled(false);
		panel.add(startButton);
				
		startButton.setText("Start");
		startButton.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				startButtonActionPerformed(evt);
			}
		});
		
		jPanel1.setLayout(jPanel1Layout);

		javax.swing.GroupLayout layout = new javax.swing.GroupLayout(
				getContentPane());
		getContentPane().setLayout(layout);
		layout.setHorizontalGroup(layout.createParallelGroup(
				javax.swing.GroupLayout.Alignment.LEADING).addComponent(
				jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE,
				javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE));
		layout.setVerticalGroup(layout.createParallelGroup(
				javax.swing.GroupLayout.Alignment.LEADING).addComponent(
				jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE,
				javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE));

		setExtendedState(JFrame.MAXIMIZED_BOTH);
		pack();
	}

	private void startButtonActionPerformed(java.awt.event.ActionEvent evt) {
		this.ipv6SnifferControl.startOrStopCapture();
	}

	private void tableSelectActionPerformed(ListSelectionEvent e) {
		if (!e.getValueIsAdjusting()) {
			Object selected = this.packetTable.getModel().getValueAt(
					this.packetTable.getSelectedRow(), 0);
			if(selected != null) {
			    btnAbrirPacote.setEnabled(true);
			} else {
			    btnAbrirPacote.setEnabled(false);
			}
			this.ipv6SnifferControl.updateDetailPacketTree(Integer
					.valueOf(selected + ""));
			for (int i = 0; i < detailPacketTree.getRowCount(); i++) {
				detailPacketTree.expandRow(i);
			}
			
			btnAbrirPacote.setEnabled(true);
		}
	}
}
