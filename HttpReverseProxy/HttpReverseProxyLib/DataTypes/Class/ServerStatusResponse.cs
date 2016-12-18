namespace HttpReverseProxyLib.DataTypes
{
  public class ServerStatusResponse
  {

    #region MEMBERS

    private string httpVersion;
    private string statusCode;
    private string statusDescription;

    #endregion


    #region PROPERTIES

    public string HttpVersion { get { return this.httpVersion; } set { this.httpVersion = value; } }

    public string StatusCode { get { return this.statusCode; } set { this.statusCode = value; } }

    public string StatusDescription { get { return this.statusDescription; } set { this.statusDescription = value; } }

    #endregion


    #region PUBLIC

    public void Reset()
    {
      httpVersion = string.Empty;
      statusCode = string.Empty;
      statusDescription = string.Empty;
    }

    #endregion

  }
}
