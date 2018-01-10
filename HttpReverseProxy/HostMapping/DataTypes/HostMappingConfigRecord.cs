namespace HttpReverseProxy.Plugin.HostMapping.DataTypes
{

  public class HostMappingConfigRecord
  {

    #region MEMBERS

    private string requestedHost = string.Empty;

    private string mappingHost = string.Empty;

    #endregion


    #region PUBLIC

    public HostMappingConfigRecord()
    {
    }

    public HostMappingConfigRecord(string requestedHost, string mappingHost)
    {
      this.requestedHost = requestedHost;
      this.mappingHost = mappingHost;
    }

    #endregion

  }
}
