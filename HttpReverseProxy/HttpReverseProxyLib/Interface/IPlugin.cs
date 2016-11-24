namespace HttpReverseProxyLib.Interface
{
  using HttpReverseProxyLib.DataTypes;


  public class PluginProperties
  {

    #region MEMBERS

    public string Name { get; set; }

    public int Priority { get; set; }

    public string Version { get; set; }

    public string PluginDirectory { get; set; }

    public bool IsActive { get; set; }

    public IPluginHost PluginHost { get; set; }

    #endregion


    #region PUBLIC

    public PluginProperties()
    {
    }

    #endregion

  }


  public interface IPlugin : System.IComparable<IPlugin>
  {

    PluginProperties Config { get; set; }

    void OnLoad(IPluginHost pluginHost);

    void OnUnload();

    PluginInstruction OnPostClientHeadersRequest(RequestObj requestObj);

    PluginInstruction OnPostServerHeadersResponse(RequestObj requestObj);

    void OnPostServerDataResponse(RequestObj requestObj, DataPacket datapacket);
  }
}
