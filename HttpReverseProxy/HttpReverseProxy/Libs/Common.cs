using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;

namespace HTTPReverseProxyServer
{
    public class Common
    {

        #region PUBLIC METHODS

        public static String getLocalIPAddress()
        {
            String lRetVal = String.Empty;

            foreach (NetworkInterface lItem in NetworkInterface.GetAllNetworkInterfaces())
            {
                if ((lItem.NetworkInterfaceType == NetworkInterfaceType.Ethernet ||lItem.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ) && 
                    lItem.OperationalStatus == OperationalStatus.Up)
                {
                    IPInterfaceProperties lAdapterProperties = lItem.GetIPProperties();
                    GatewayIPAddressInformation lGWInfo = lAdapterProperties.GatewayAddresses.FirstOrDefault();

                    if (lGWInfo != null && lGWInfo.Address != null)
                    {
                        foreach (UnicastIPAddressInformation lTmpIP in lItem.GetIPProperties().UnicastAddresses)
                        {
                            if (lTmpIP.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                lRetVal = lTmpIP.Address.ToString();
                                break;
                            } // if (ip.Add...
                        } // foreach ...
                    } // if (lGWIn...
                } // if (item...
            } // foreach (Network...

            return lRetVal;
        }



        /*
         * 
         * 
         */
        public static Int32 ConvertIPToInt32(IPAddress pIPAddr)
        {
            byte[] lByteAddress = pIPAddr.GetAddressBytes();
            return BitConverter.ToInt32(lByteAddress, 0);
        }


        #endregion

    }
}
