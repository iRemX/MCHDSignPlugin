using EncryptionCore;
using SBPluginInterfaceLibrary;

namespace SPStandardEncryption
{
    /// <summary>
    /// Класс, являющийся входной точкой для загрузчика плагина.
    /// </summary>
    public static class StartPoint
    {
        /// <summary>
        /// Получить интерфейс плагина.
        /// </summary>
        /// <returns>Интерфейс плагина.</returns>
        public static IPlugin2 GetInterface()
        {
            return new EncryptionPlugin();
        }
    }
}
