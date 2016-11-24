namespace HttpReverseProxy.Plugin.HostMapping.DataTypes
{

  public class HostMappingConfigRecord
  {

    #region MEMBERS

    private string requestedHost;
    private string mappingHost;

    #endregion


    #region PROPERTIES

    public string RequestedHost { get { return this.requestedHost; } set { this.requestedHost = value; } }

    public string MappingHost { get { return this.mappingHost; } set { this.mappingHost = value; } }

    #endregion


    #region PUBLIC

    public HostMappingConfigRecord()
    {
      this.requestedHost = string.Empty;
      this.mappingHost = string.Empty;
    }

    public HostMappingConfigRecord(string requestedHost, string mappingHost)
    {
      this.requestedHost = requestedHost;
      this.mappingHost = mappingHost;
    }

    #endregion

  }
}
