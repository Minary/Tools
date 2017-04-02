
namespace HttpReverseProxyLib.DataTypes.Enum
{
  using System;


  [Flags]
  public enum Loglevel : int
  {
    Debug = 1,
    Info = 2,
    Warning = 3,
    Error = 4
  }
}
