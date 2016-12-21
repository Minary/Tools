
namespace HttpReverseProxyLib.DataTypes.Enum
{
  using System;


  [Flags]
  public enum Loglevel : int
  {
    DEBUG = 1,
    INFO = 2,
    WARNING = 3,
    ERROR = 4
  }
}
