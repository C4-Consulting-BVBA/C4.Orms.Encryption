using AutoMapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Text;

namespace C4.Orms.Encryption.Test
{
    public class TestBase
    {
        protected static IMapper ConfigureMapper(Action<IMapper> mapper)
        {
            var mapperConfiguration = new MapperConfiguration(config =>
            {
                //config.AddProfile(new MapperProfile());
                config.ForAllMaps((typeMap, mappingExpression) => mappingExpression.MaxDepth(1));
            });

            mapperConfiguration.AssertConfigurationIsValid();

            return mapperConfiguration.CreateMapper();
        }

        protected static ServiceProvider ConfigureProvider(Action<IServiceCollection> configure)
        {
            var services = new ServiceCollection();

            services.AddLogging(configure => configure.AddConsole());

            configure(services);

            return services.BuildServiceProvider();
        }
    }
}
