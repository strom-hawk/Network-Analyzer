package networkanalyzer;

import javax.swing.*;
import jpcap.*;
import network.analyzer.DetectDevice;
import network.analyzer.NetworkAnalyzer;

public class OpenDevice extends Thread implements Runnable
{
    DetectDevice ddobj = new DetectDevice();
    NetworkAnalyzer obj = new NetworkAnalyzer(false);
    public int index = 0;
    public static JpcapCaptor selectedDevice;
    public String packet = null;
    public boolean captureFlag;
    public int numPackets;
    
    public void run()
    {
        
        try
        {
            selectedDevice = JpcapCaptor.openDevice(ddobj.deviceList[index], 65535, false, 20);
            numPackets = 0;
            captureFlag = true;
            System.out.println("Device successfully opened");
        }
        catch(Exception E)
        {
            JOptionPane.showMessageDialog(null, "Permission Denied");
            E.printStackTrace();
        }
        while(captureFlag == true)
        {
            try
            {
                packet = (selectedDevice.getPacket()).toString();
                ++numPackets;
                Thread.sleep(100);
            }
            catch(InterruptedException E)
            {
                captureFlag = false;
            }
            catch(Exception E)
            {
                packet = "null";
            }
        }
    }
}