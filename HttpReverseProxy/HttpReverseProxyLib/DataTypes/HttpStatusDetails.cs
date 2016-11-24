namespace HttpReverseProxyLib.DataTypes
{
  public class HttpStatusDetails
  {

    #region MEMBERS

    private int code = 0;
    private string title = string.Empty;
    private string description = string.Empty;

    #endregion


    #region PROPERTIES

    public int Code { get { return this.code; } set { } }
    public string Title { get { return this.title; } set { } }
    public string Description { get { return this.description; } set { } }

    #endregion


    #region PUBLIC

    public HttpStatusDetails(int code, string title, string description)
    {
      this.code = code;
      this.title = title;
      this.description = description;
    }

    #endregion

  }
}
