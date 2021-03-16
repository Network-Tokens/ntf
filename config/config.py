import yamale


BASE_CONFIG_SCHEMA = 'schema/config-base.yaml'


class NtfConfig:
    def __init__(self, filename=None, data=None):
        if data:
            self.data = data
        elif filename:
            self.data = yamale.make_data(filename)

        # Ensure the base configuration is valid.  Validate with strict=False
        # because there will be options we don't recognize until we know the
        # NTF & token insert type.
        schema = yamale.make_schema(BASE_CONFIG_SCHEMA)
        yamale.validate(schema, self.data, strict=False)

        # Valid base config - add schemas
        ntf_app = self.data[0][0]['ntf_app']

        for prop_name in ['ntf_type', 'token_insert']:
            prop_value = ntf_app[prop_name]
            schema_filename = 'schema/%s_%s.yaml' % (prop_name, prop_value)

            try:
                s = yamale.make_schema(schema_filename)
            except FileNotFoundError:
                msg = 'No schema definition for %s: %s'
                raise Exception(msg % (prop_name, prop_value))
            for key, value in s.dict.items():
                schema.includes['ntf_app_config'].dict[key] = value

        # Revalidate with strict schema
        yamale.validate(schema, self.data)

