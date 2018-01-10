namespace HttpReverseProxyLib.DataTypes.Class
{

  public class HttpStatusDetails
  {

    #region PROPERTIES

    public int Code { get; private set; }

    public string Title { get; private set; }

    public string Description { get; private set; }

    #endregion


    #region PUBLIC

    public HttpStatusDetails(int code, string title, string description)
    {
      this.Code = code;
      this.Title = title;
      this.Description = description;
    }

    #endregion

  }
}
