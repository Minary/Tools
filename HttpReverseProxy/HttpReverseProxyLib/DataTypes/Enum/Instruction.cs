namespace HttpReverseProxyLib.DataTypes
{
  public enum Instruction : int
  {
    DoNothing = 0,
    RedirectToNewUrl = 1,
    SendBackStatus = 2,
    ReloadUrl = 3,
    RefreshUrl = 4,
    ReloadUrlWithHttps = 5,
    SendBackLocalFile = 6
  }
}
