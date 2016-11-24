namespace HttpReverseProxy.Plugin.Inject.DataTypes
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Text;
  using System.Threading.Tasks;


  public class InjectConfigRecord
  {

    #region MEMBERS

    private string host;
    private string path;
    private InjectType type;
    private string replacementResource;

    #endregion


    #region PROPERTIES

    public string Host { get { return this.host; } set { this.host = value; } }

    public string Path { get { return this.path; } set { this.path = value; } }

    public InjectType Type { get { return this.type; } set { this.type = value; } }

    public string ReplacementResource { get { return this.replacementResource; } set { this.replacementResource = value; } }

    #endregion


    #region PUBLIC

    public InjectConfigRecord()
    {
      this.type = InjectType.URL;
      this.host = string.Empty;
      this.path = string.Empty;
      this.replacementResource = string.Empty;
    }

    public InjectConfigRecord(InjectType type, string host, string path, string replacementResource)
    {
      this.type = type;
      this.host = host;
      this.path = path;
      this.replacementResource = replacementResource;
    }

    #endregion 

  }
}
