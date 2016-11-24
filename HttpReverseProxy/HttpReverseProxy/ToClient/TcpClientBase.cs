using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using HttpReverseProxyLib.Exceptions;


namespace HttpReverseProxy.ToClient
{

  public class TcpClientBase
  {

    #region MEMBERS



    #endregion


    #region PUBLIC

    public void SendToClient(byte[] data, BinaryWriter writer)
    {
      if (data == null)
      {
        throw new ProxyWarningException("Data array is invalid");
      }

      if (writer == null)
      {
        throw new ProxyWarningException("Writer object is invalid");
      }

      if (data.Length <= 0)
      {
        return;
      }

      writer.Write(data, 0, data.Length);

    }

    #endregion 

  }
}
