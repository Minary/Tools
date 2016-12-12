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

    public string HttpVersion { get { return httpVersion; } set { httpVersion = value; } }
    public string StatusCode { get { return statusCode; } set { statusCode = value; } }
    public string StatusDescription { get { return statusDescription; } set { statusDescription = value; } }

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
