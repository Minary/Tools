using HttpReverseProxyLib.DataTypes.Class;
using HttpReverseProxyLib.DataTypes.Class.Client;
using HttpReverseProxyLib.DataTypes.Enum;
using HttpReverseProxyLib.DataTypes.Interface;
using HttpReverseProxyLib;

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;


namespace TestsPlugins
{
  public class HelperMethods
  {

    #region MEMBERS

    private static HelperMethods inst;

    #endregion


    #region PROPERTIES

    public static HelperMethods Inst { get { return inst ?? (inst = new HelperMethods()); } }

    #endregion 


    #region PUBLIC

    public DataChunk GenerateDataChunk()
    {
      var dataString = "<html><title>le titre</title><body>hello world out there!!</body></html>";
      byte[] data = Encoding.ASCII.GetBytes(dataString);
      DataChunk chunk = new DataChunk(data, data.Length, Encoding.UTF8);

      return chunk;
    }


    public RequestObj GenerateBasicRequest(string scheme, string host, string path)
    {
      var reqObj = new RequestObj("minary.io", ProxyProtocol.Http);
      reqObj.ClientRequestObj.Scheme = scheme;
      reqObj.ClientRequestObj.Host = host;
      reqObj.ClientRequestObj.ClientRequestHeaders = new Dictionary<string, List<string>>() { { "Host", new List<string>() { host } } };

      reqObj.ClientRequestObj.RequestLine = new ClientRequestLine();
      reqObj.ClientRequestObj.RequestLine.HttpVersion = "1.1";
      reqObj.ClientRequestObj.RequestLine.MethodString = "GET";
      reqObj.ClientRequestObj.RequestLine.NewlineBytes = Encoding.ASCII.GetBytes("\n");
      reqObj.ClientRequestObj.RequestLine.NewlineType = Newline.LF;
      reqObj.ClientRequestObj.RequestLine.Path = path;
      reqObj.ClientRequestObj.RequestLine.RequestLine = $"{reqObj.ClientRequestObj.RequestLine.MethodString} {reqObj.ClientRequestObj.RequestLine.Path} {reqObj.ClientRequestObj.RequestLine.HttpVersion}";
      reqObj.ClientRequestObj.RequestLine.RequestMethod = RequestMethod.GET;

      return reqObj;
    }
    

    public IPluginHost GeneratePluginHost()
    {
      IPluginHost retVal = new PluginHost();

      return retVal;
    }


    public void RemoveFile(string path)
    {
      if (File.Exists(path))
      {
        try
        {
          File.Delete(path);
        }
        catch (Exception ex)
        {
          Console.WriteLine($"TestClean(EXC): {ex.Message}");
        }
      }
    }

    #endregion



    #region PRIVATE

    private class PluginHost : IPluginHost
    {
      public Logging LoggingInst { get; set; }

      public void RegisterPlugin(IPlugin pluginData)
      {
        //throw new NotImplementedException();
      }

      public PluginHost()
      {
        this.LoggingInst = HttpReverseProxyLib.Logging.Instance;
      }
    }

    #endregion

  }
}
