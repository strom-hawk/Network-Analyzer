package network.analyzer;

import jpcap.*;

public class DetectDevice
{
    public static NetworkInterface[] deviceList;
    public static String[] devices;
    
    public String[] getDeviceList()
    {
        deviceList = JpcapCaptor.getDeviceList();
        devices = new String[deviceList.length];
        System.out.println("Available devices:");
        for(int i=0; i<deviceList.length; i++)
        {
            try
            {
                devices[i] = deviceList[i].name.toString();
            }
            catch(Exception E)
            {
                devices[i] = "Null";
            }
        }
        return (devices);
    }
}