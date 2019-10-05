package network.analyzer;

import jpcap.*;
import javax.swing.*;
import javax.swing.border.Border;
import java.awt.Color;
import java.awt.*;
import java.awt.geom.Line2D;
import java.awt.event.*;
import networkanalyzer.OpenDevice;

public class NetworkAnalyzer extends JFrame implements ActionListener
{
    DetectDevice obj = new DetectDevice();          //OBJECT OF DETECT DEVICE CLASS
    
    private boolean init = true;                    //FOR INITIALIZING THE GUI
    public final int width = 1000;                  //WIDTH OF GUI
    public final int height = 600;                  //HEIGHT OF GUI
    public JFrame mainFrame;                        //MAIN FRAME WINDOW
    
            
    //----------------------------->
    //MENU BAR COMPONENTS
    public JMenuBar mbar;
    //FILE MENU
    public JMenu file;
    JMenuItem exitMenu;
    JMenuItem restartMenu;
    JMenuItem saveMenu;
    
    //CAPTURE MENU
    public JMenu capture;
    JMenuItem detectInterfaces;
    JMenuItem refreshInterfaces;
    JMenuItem stopMenu;
    JMenuItem startMenu;
    JMenuItem homeMenu;
    
    //ANALYSIS MENU
    public JMenu analysis;
    public JMenuItem packetGraph;
    
    
    //HELP MENU
    public JMenu help;
        
    //----------------------------->
    //PANEL1 COMPONENTS
    private JPanel panel1;
    public JButton start;
    public JButton stop;
    public JButton home;
    public JButton save;
    String saveToFile;
    public JLabel filterText;
    public JTextField filter;
    
    //----------------------------->
    //PANEL2 COMPONENTS
    public JPanel panel2;
    public JLabel label1;
    private JButton button1;
    public JList<String> deviceSelectionList;       //DEVICE LIST
    String[] deviceList;
    public int index = 0;                           //SELECTED INTERFACE NUMBER
    DefaultListModel listModel;                     //FOR ADDING PACKET CAPTURED
    JList<String> packetList;                       //LIST CONTAINING PACKETS
    JScrollPane packetScrollBar;                    //SCROLLBAR FOR PACKET LIST
    Border border = BorderFactory.createLineBorder(Color.BLACK);
    public Timer timer;
    OpenDevice deviceObj;
    JLabel icon;
            
    //----------------------------->
    //PANEL3 COMPONENTS
    public JPanel panel3;
    JLabel deviceLabel;
    JLabel deviceStatus;
    JLabel packet;
    JLabel packetCount;
    
    //----------------------------->
    //PANEL4 COMPONENTS
    JPanel panel4;
    JButton closeP4;
    int tcp;
    int udp;
    int arp;
    int other;
    
    //----------------------------->
    //CONSTRUCTOR
    public NetworkAnalyzer(boolean init)
    {
        if(init == true){
        //----------------------------->
        //CREATES MAIN FRAME FOR PROGRAM
        mainFrame = new JFrame("NETWORK ANALYZER //");
        mainFrame.setSize(width,height);
        mainFrame.setLocation(200,50);
        mainFrame.setResizable(false);
        
        //----------------------------->
        //CREATES PANEL1 AT TOP FOR MENU
        panel1 = new JPanel();
        panel1.setLayout(null);
        panel1.setBounds(0,5,width,80);
        //panel1.setBackground(Color.white);
        addComponentsPanel1();
        mainFrame.add(panel1);
        //----------------------------->
        //CREATES PANEL2 AT TOP FOR MENU
        panel2 = new JPanel();
        panel2.setLayout(null);
        panel2.setBounds(100,150,700,300);
        //panel2.setBackground(Color.lightGray);    /////////////////////////////
        addComponentsPanel2();
        mainFrame.add(panel2, BorderLayout.CENTER);
        //----------------------------->
        //CREATES PANEL3 AT BOTTOM FOR STATUS
        panel3 = new JPanel();
        panel3.setLayout(null);
        panel3.setBounds(0,height-40,width,20);
        panel3.setBackground(new Color(200,200,200));
        //panel3.setBorder(BorderFactory.createCompoundBorder(border, BorderFactory.createEmptyBorder(0, 0, 0, 0)));
        addComponentsPanel3();
        mainFrame.add(panel3);
        //----------------------------->     
        mainFrame.setLayout(null);
        mainFrame.setVisible(true);
        mainFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        //MAIN FRAME CLOSE
        //----------------------------->
        }
    }
    
    //----------------------------->
    public void addComponentsPanel1()
    {
        //----------------------------->
        //ADDING HOME BUTTON
        home = new JButton();
        home.setActionCommand("home");
        home.setEnabled(true);
        home.setIcon(new ImageIcon("/home/saurav/NetBeansProjects/Network Analyzer/Icon/home.png"));
        home.setBounds(5,0,50,50);
        home.addActionListener(new EventHandling(this));
        //----------------------------->
        //ADDING START BUTTON
        start = new JButton();
        start.setActionCommand("start");
        start.setIcon(new ImageIcon("/home/saurav/NetBeansProjects/Network Analyzer/Icon/start.png"));
        start.setEnabled(true);
        start.setBounds(65,0,50,50);
        start.addActionListener(new EventHandling(this));
        //----------------------------->
        //ADDING STOP BUTTON
        stop = new JButton();
        stop.setActionCommand("stop");
        stop.setIcon(new ImageIcon("/home/saurav/NetBeansProjects/Network Analyzer/Icon/stop.png"));
        stop.setEnabled(false);
        stop.setBounds(125,0,50,50);
        stop.addActionListener(new EventHandling(this));
        //----------------------------->
        //ADDING SAVE BUTTON
        save = new JButton();
        save.setActionCommand("save");
        save.setEnabled(true);
        save.setBounds(205,0,50,50);
        save.setIcon(new ImageIcon("/home/saurav/NetBeansProjects/Network Analyzer/Icon/save.png"));
        save.addActionListener(new EventHandling(this));
        //----------------------------->
        //ADDING FILTER LABEL
        filterText = new JLabel("Filter: ");
        filterText.setFont(new Font("Tahoma", Font.BOLD, 15));
        filterText.setForeground(Color.black);
        filterText.setBackground(mainFrame.getBackground());
        filterText.setBorder(BorderFactory.createCompoundBorder(border, BorderFactory.createEmptyBorder(5, 0, 0, 0)));
        filterText.setBounds(0,55,55,20);
        //----------------------------->
        //ADDING FILTER TEXT FIELD
        filter = new JTextField();
        filter.setActionCommand("filterPackets");
        filter.setBounds(55,55,width,20);
        filter.setBorder(BorderFactory.createCompoundBorder(border, BorderFactory.createEmptyBorder(0, 0, 0, 0)));
        filter.addActionListener(new EventHandling(this));
        //----------------------------->
        //ADDING MENU BAR
        mbar = new JMenuBar();
        mbar.setFont(new Font("Tahoma",Font.BOLD, 14));
        mainFrame.setJMenuBar(mbar);
        //----------------------------->
        //ADDING TO FILE MENU
        file = new JMenu("File");
        saveMenu = new JMenuItem("Save");
        saveMenu.addActionListener(new EventHandling(this));
        
        restartMenu = new JMenuItem("Restart Application");
        restartMenu.addActionListener(new EventHandling(this));
        
        exitMenu = new JMenuItem("Exit");
        exitMenu.addActionListener(new EventHandling(this));
        
        file.add(saveMenu);
        file.add(restartMenu);
        file.add(exitMenu);
        //----------------------------->
        //ADDING TO CAPTURE MENU
        capture = new JMenu("Capture");
        
        homeMenu = new JMenuItem("Home");
        homeMenu.addActionListener(new EventHandling(this));
        
        startMenu = new JMenuItem("Start Capturing");
        startMenu.addActionListener(new EventHandling(this));
        
        stopMenu = new JMenuItem("Stop Capturing");
        stopMenu.addActionListener(new EventHandling(this));
        
        refreshInterfaces = new JMenuItem("Refresh Interfaces");
        refreshInterfaces.addActionListener(new EventHandling(this));
        
        detectInterfaces = new JMenuItem("Detect Interfaces");
        detectInterfaces.addActionListener(this);
        
        
        capture.add(homeMenu);
        capture.add(startMenu);
        capture.add(stopMenu);
        capture.add(refreshInterfaces);
        capture.add(detectInterfaces);
        //----------------------------->
        //ADDING TO ANALYSIS MENU
        analysis = new JMenu("Analysis");
        
        packetGraph = new JMenuItem("Create Packet Graph");
        packetGraph.addActionListener(new EventHandling(this));
        
        
        analysis.add(packetGraph);
        //----------------------------->
        //ADDING TO HELP MENU
        help = new JMenu("Help");
        
        JMenuItem aboutMenu = new JMenuItem("About Us");
        aboutMenu.addActionListener(new EventHandling(this));
        
        help.add(aboutMenu);
        //----------------------------->
        //ADDING MENUITEMS TO MENUBAR
        mbar.add(file);
        mbar.add(capture);
        mbar.add(analysis);
        mbar.add(help);
        //----------------------------->
        //ADDING ALL TO PANEL1
        panel1.add(home);
        panel1.add(start);
        panel1.add(stop);
        panel1.add(save);
        panel1.add(filterText);
        panel1.add(filter);
        //----------------------------->
    }
    
    
    //----------------------------->
    public void addComponentsPanel2()
    {
        //----------------------------->
        //ADDING LABEL
        label1 = new JLabel("Welcome To Network Analyzer");
        Font font = new Font("Comic Sans", Font.BOLD, 18);
        //label1.setOpaque(true);
        //label1.setBackground(new Color(59,89,182));       
        label1.setForeground(Color.blue);
        label1.setFont(font);
        label1.setBounds(0,0,310,40);
        panel2.add(label1);
        //----------------------------->
        //ADDING ICON AFTER label1
        icon = new JLabel();
        icon.setIcon(new ImageIcon("/home/saurav/NetBeansProjects/Network Analyzer/Icon/updown.png"));
        icon.setBounds(310,-25,100,100);
        panel2.add(icon);
        //----------------------------->
        //ADDING DETECT DEVICE BUTTON
        button1 = new JButton("Detect Devices");
        button1.setBounds(0,40,140,25);
        button1.setBackground(new Color(59,89,182));
        button1.setForeground(Color.white);
        button1.setFocusPainted(false);
        button1.setFont(new Font("Tahoma", Font.BOLD, 12));
        button1.addActionListener(this);
        panel2.add(button1);
        //BUTTON1 ADDED
        //----------------------------->
    }
    
    //----------------------------->
    //ADDING COMPONENTS TO PANEL3 FOR STATUS
    public void addComponentsPanel3()
    {
        //ADDING DEVICE STATUS LABEL
        deviceLabel = new JLabel("Selected Device: ");
        deviceLabel.setBounds(0,0,130,20);
        
        //ADDING DEVICE STATUS
        deviceStatus = new JLabel("null");
        deviceStatus.setBounds(130,0,130,20);
        
        //ADDING PACKET LABEL
        packet = new JLabel("Packets: ");
        packet.setBounds(width/2,0,100,20);
        
        //ADDING PACKET COUNT;
        packetCount  = new JLabel("0");
        packetCount.setBounds((width/2)+70,0,100,20);
        
        
        //ADDING ALL TO PANEL3
        panel3.add(deviceLabel);
        panel3.add(deviceStatus);
        panel3.add(packet);
        panel3.add(packetCount);
        //----------------------------->
    }
    //----------------------------->
    //CHANGE THE DEVICE STATUS IN PANEL3
    public void captureInterface(int index)
    {
        deviceStatus.setText(deviceList[index]);
    }

    //----------------------------->
    public void actionPerformed(ActionEvent ae)
    {
        String msg = ae.getActionCommand();
        if (msg.equals("Detect Devices") || msg.equals("Detect Interfaces"))
        {   
            obj = new DetectDevice();
            deviceList  = obj.getDeviceList();
            deviceSelectionList = new JList<String>(deviceList);
            deviceSelectionList.setFont(new Font("Tahoma", Font.BOLD, 15));
            deviceSelectionList.setBackground(mainFrame.getBackground());
            deviceSelectionList.setForeground(Color.darkGray);
            deviceSelectionList.setBounds(0,80,300,200);
            
            panel2.add(deviceSelectionList);        
            mainFrame.repaint();
            deviceSelectionList.addMouseListener(new EventHandling(this));
        }
    }
    //----------------------------->
    public void capturePackets(int index)
    {
        detectInterfaces.setEnabled(false);
        startMenu.setEnabled(false);
        start.setEnabled(false);
        stop.setEnabled(true);
        panel2.remove(label1);
        panel2.remove(icon);
        panel2.remove(button1);
        panel2.remove(deviceSelectionList);
        panel2.setBounds(0,100,width,height/2);
        
        listModel = new DefaultListModel();
        packetList = new JList<String>(listModel);
        packetScrollBar = new JScrollPane(packetList);
        packetScrollBar.setLocation(0,0);
        packetScrollBar.setSize(new Dimension(width, (height/2)-40));
        packetScrollBar.setBorder(BorderFactory.createCompoundBorder(border, BorderFactory.createEmptyBorder(0, 0, 0, 0)));
        panel2.add(packetScrollBar);
        
        
        //MULTITHREADING APPLIED HERE SO AS TO CAPTURE PACKETS SIMULTANEOUSLY
        deviceObj = new OpenDevice();
        deviceObj.index = index;
        deviceObj.start();
    
        //------------------------------>
        timer = new Timer(100, new ActionListener() {
        public void actionPerformed(ActionEvent evt) 
        {
            //ADDS THE PACKET TO THE LIST
            String packet = deviceObj.packet.toString();
            saveToFile = saveToFile + packet + '\n';
            //listModel.addElement(packet);            //ADDS TO THE END OF THE LIST
            listModel.insertElementAt(packet,0);       //ADDS TO THE TOP OF THE LIST
            //ADDS THE NUMBER OF PACKETS CAPTURED
            String temp = Integer.toString(deviceObj.numPackets);
            packetCount.setText(temp);
            panel3.repaint(); 
        }
        });
   
        timer.setRepeats(true);
        timer.start();
    }
    
    public void interrupt()
    {
        deviceObj.interrupt();
        timer.stop();
        start.setEnabled(true);
        stop.setEnabled(false);
        startMenu.setEnabled(true);
        stopMenu.setEnabled(false);
    }
    
    //----------------------------->
    //BAR GRAPH SECTION
    public void barGraph()
    {       
        mainFrame.remove(panel2);                           //REMOVES PANEL2
        
        panel4 = new JPanel();                            //NEW PANEL FOR BAR GRAPH
        panel4.setLayout(null);
        panel4.setBounds(0, 80, width, height-140);
        
        closeP4 = new JButton();
        closeP4.setActionCommand("close panel 4");
        closeP4.setBounds(970,30,16,16);
        closeP4.addActionListener(new EventHandling(this));
        closeP4.setVisible(true);
        closeP4.setBorderPainted(false);
        closeP4.setIcon(new ImageIcon("/home/saurav/NetBeansProjects/Network Analyzer/Icon/closep4.png"));
        
        panel4.add(closeP4);
        mainFrame.add(panel4);
        //----------------------------->
        //DETAILS DISPLAY SECTION
        Graphics g = panel4.getGraphics();
        
        
        //----------------------------->
        //GRPAH DRAWING SECTION
        g.setColor(new Color(149,165,166));              //CONCRETE COLOR
        g.fillRect(0,20, width, height-160);             //DRAWS A RECTANGLE OVER THE ENTIRE AREA
        
        //X AXIS SECTION
        g.setColor(new Color(236,240,241));              //CLOUDS COLOR
        g.drawLine(250,400,800,400);
        g.drawLine(250,401,800,401);
        g.drawString(">", 798, 405);
        g.drawString("X Axis", 760,420);
        //Y AXIS SECTION
        g.drawLine(250,50,250,400);
        g.drawLine(251,50,251,400);
        g.drawString("^", 246, 59);
        g.drawString("Y Axis", 200,70);
        //50 IN Y AXIS
        g.drawLine(247,350,254,350);
        g.drawLine(247,351,254,351);
        g.drawString("50", 220, 355);        
        //100 IN Y AXIS
        g.drawLine(247,300,254,300);
        g.drawLine(247,301,254,301);
        g.drawString("100", 210, 305);
        //150 IN Y AXIS
        g.drawLine(247,250,254,250);
        g.drawLine(247,251,254,251);
        g.drawString("150", 210, 255);
        //200 IN Y AXIS
        g.drawLine(247,200,254,200);
        g.drawLine(247,201,254,201);
        g.drawString("200", 210, 205);
        //250 IN Y AXIS
        g.drawLine(247,150,254,150);
        g.drawLine(247,151,254,151);
        g.drawString("250", 210, 155);
        //300 IN Y AXIS
        g.drawLine(247,100,254,100);
        g.drawLine(247,101,254,101);
        g.drawString("300", 210, 105);
        //TCP BAR
        g.setColor(new Color(192, 57, 43));
        g.fillRect(350, 400-tcp, 50, 400-(400-tcp));
        g.drawString(Integer.toString(tcp), 365, 400-tcp-10);
        g.drawString("TCP", 365, 420);
        //UDP BAR
        g.setColor(new Color(44, 62, 80));
        g.fillRect(400, 400-udp, 50, 400-(400-udp));
        g.drawString(Integer.toString(udp), 415, 400-udp-10);
        g.drawString("UDP", 415, 420);
        //ARP BAR
        g.setColor(new Color(27, 119, 66));
        g.fillRect(450, 400-arp, 50, 400-(400-arp));
        g.drawString(Integer.toString(arp), 465, 400-arp-10);
        g.drawString("ARP", 465, 420);
        //OTHER BAR
        g.setColor(new Color(169, 67, 0));
        g.fillRect(500, 400-other, 50, 400-(400-other));
        g.drawString(Integer.toString(other), 515, 400-other-10);
        g.drawString("OTHER", 515, 420);
        //CLOSE BUTTON
        Graphics2D g2 = (Graphics2D) g;
        g2.setStroke(new BasicStroke(2));
        g2.setColor(new Color(236,240,241));
        g2.drawLine(971,31,985,45);
        g2.drawLine(984,31,971,44);
        //GRAPH DRAWN
    }
    
    //----------------------------->
    //MAIN METHOD SECTION
    public static void main(String[] args)
    {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() 
            {
                NetworkAnalyzer networkObject = new NetworkAnalyzer(true);
            }
        });
    }
}
