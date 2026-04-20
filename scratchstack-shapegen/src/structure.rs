use {
    super::{Member, Typed, to_snake_case},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    std::{
        collections::HashMap,
        io::{Result as IoResult, Write},
    },
};

/// The structure type represents a fixed set of named, unordered, heterogeneous values. A
/// structure shape contains a set of named members, and each member name maps to exactly one
/// member definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Structure {
    /// The name of this structure in the Smithy model.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub smithy_typename: Option<String>,

    /// The Rust name of this structure.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub rust_typename: Option<String>,

    /// Whether this struct is reachable from an API input shape. This is used to determine
    /// whether to generate Clap parsers for this struct.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub reachable_from_input: bool,

    /// The members of the structure. Each member name maps to exactly one member definition.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub members: HashMap<String, Member>,

    /// Traits to apply to the type.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub traits: HashMap<String, Value>,
}

impl Structure {
    /// Writes the Rust declaration for the main body of this structure.
    fn write_rust_decl(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        let docs = self.traits.get("smithy.api#documentation").and_then(|v| v.as_str());
        if let Some(docs) = docs {
            for line in docs.lines() {
                writeln!(output, "/// {}", line.trim())?;
            }
        } else {
            writeln!(output, "#[allow(missing_docs)]")?;
        }

        writeln!(output, "#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]")?;
        writeln!(output, "#[builder(pattern = \"owned\", build_fn(validate = \"Self::validate\"))]")?;

        if self.reachable_from_input {
            writeln!(output, "#[cfg_attr(feature = \"clap\", derive(::clap::Parser))]")?;
        }

        writeln!(output, "pub struct {rust_typename} {{")?;

        let mut is_first = true;
        for (member_name, member) in &self.members {
            if !is_first {
                writeln!(output)?;
            } else {
                is_first = false;
            }

            let docs = member.traits.get("smithy.api#documentation").and_then(|v| v.as_str());
            if let Some(docs) = docs {
                for line in docs.lines() {
                    writeln!(output, "    /// {}", line.trim())?;
                }
            } else {
                writeln!(output, "    #[allow(missing_docs)]")?;
            }

            let is_optional = member.is_optional();
            let is_list = member.is_list();
            if self.reachable_from_input {
                let mut clap_args = vec!["long".to_string()];
                if is_optional && !is_list {
                    clap_args.push("default_value = \"None\"".to_string());
                }
                clap_args.push(format!("value_parser = {}", member.get_clap_parser(is_optional)));
                writeln!(output, "    #[cfg_attr(feature = \"clap\", clap({}))]", clap_args.join(", "))?;
            }

            let mut member_type = member.rust_typename();
            let rust_member_name = to_snake_case(member_name);

            if is_optional && !is_list {
                member_type = format!("Option<{}>", member_type);
            }

            writeln!(output, "    #[serde(rename = \"{member_name}\")]")?;
            if is_optional || is_list {
                writeln!(output, "    #[builder(default)]")?;
            }
            writeln!(output, "    pub {rust_member_name}: {member_type},")?;
        }

        writeln!(output, "}}")?;
        writeln!(output)?;

        Ok(())
    }

    /// Writes the main impl of this structure, which just provides a builder method for constructing this structure.
    fn write_rust_impl(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        writeln!(output, "impl {rust_typename} {{")?;
        writeln!(output, "    /// Returns a [`{rust_typename}Builder`] for constructing a `{rust_typename}`.")?;
        writeln!(output, "    pub fn builder() -> {rust_typename}Builder {{")?;
        writeln!(output, "        {rust_typename}Builder::default()")?;
        writeln!(output, "    }}")?;
        writeln!(output, "}}")?;
        writeln!(output)?;
        Ok(())
    }

    /// Writes the FromStr implementation for this structure, which is used for parsing this structure from a string
    /// when parsing Clap arguments.
    fn write_rust_from_str_impl(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        writeln!(output, "#[cfg(feature = \"clap\")]")?;
        writeln!(output, "impl FromStr for {rust_typename} {{")?;
        writeln!(output, "    type Err = String;")?;
        writeln!(output, "    fn from_str(s: &str) -> Result<Self, Self::Err> {{")?;
        writeln!(
            output,
            "        let value = crate::shorthand::parse(s).map_err(|e| format!(\"Failed to parse {rust_typename} from '{{s}}': {{e}}\"))?;"
        )?;
        writeln!(
            output,
            "        let map = value.as_map().ok_or(format!(\"Expected a map/object to parse {rust_typename}, but got '{{value:?}}'\"))?;"
        )?;

        if !self.members.is_empty() {
            writeln!(output, "        let mut builder = {rust_typename}Builder::default();")?;
            writeln!(output, "        for (key, value) in map {{")?;
            writeln!(output, "            match key.as_str() {{")?;
            for member_name in self.members.keys() {
                let rust_member_name = to_snake_case(member_name);
                writeln!(output, "                \"{member_name}\" => {{")?;
                writeln!(output, "                    builder = builder.{rust_member_name}(value.try_into()?);")?;
                writeln!(output, "                }}")?;
            }
            writeln!(
                output,
                "                other => return Err(format!(\"Unknown field '{{other}}' when parsing {rust_typename}\")),"
            )?;
            writeln!(output, "            }}")?;
            writeln!(output, "        }}")?;
            writeln!(
                output,
                "        builder.build().map_err(|e| format!(\"Failed to build {rust_typename} from '{{s}}': {{e}}\"))"
            )?;
        } else {
            writeln!(output, "        if let Some(key) = map.keys().next() {{")?;
            writeln!(
                output,
                "            return Err(format!(\"Unexpected field '{{key}}' when parsing {rust_typename}, which has no members\"));"
            )?;
            writeln!(output, "        }}")?;
            writeln!(output, "        Ok({rust_typename} {{}})")?;
        }
        writeln!(output, "    }}")?;
        writeln!(output, "}}")?;
        writeln!(output)?;
        Ok(())
    }

    fn write_rust_try_from_shorthand_value_impl(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        writeln!(output, "#[cfg(feature = \"clap\")]")?;
        writeln!(output, "impl TryFrom<&crate::shorthand::Value> for {rust_typename} {{")?;
        writeln!(output, "    type Error = String;")?;
        writeln!(output, "    fn try_from(value: &crate::shorthand::Value) -> Result<Self, Self::Error> {{")?;
        writeln!(
            output,
            "        let map = value.as_map().ok_or(format!(\"Expected a map/object to convert to {rust_typename}, but got '{{value:?}}'\"))?;"
        )?;

        if !self.members.is_empty() {
            writeln!(output, "        let mut builder = {rust_typename}Builder::default();")?;
            writeln!(output, "        for (key, value) in map {{")?;
            writeln!(output, "            match key.as_str() {{")?;
            for member_name in self.members.keys() {
                let rust_member_name = to_snake_case(member_name);
                writeln!(output, "                \"{member_name}\" => {{")?;
                writeln!(output, "                    builder = builder.{rust_member_name}(value.try_into()?);")?;
                writeln!(output, "                }}")?;
            }
            writeln!(
                output,
                "                other => return Err(format!(\"Unknown field '{{other}}' when converting to {rust_typename}\")),"
            )?;
            writeln!(output, "            }}")?;
            writeln!(output, "        }}")?;
            writeln!(
                output,
                "        builder.build().map_err(|e| format!(\"Failed to build {rust_typename} from '{{value:?}}': {{e}}\"))"
            )?;
        } else {
            writeln!(output, "        if let Some(key) = map.keys().next() {{")?;
            writeln!(
                output,
                "            return Err(format!(\"Unexpected field '{{key}}' when converting to {rust_typename}, which has no members\"));"
            )?;
            writeln!(output, "        }}")?;
            writeln!(output, "        Ok({rust_typename} {{}})")?;
        }

        writeln!(output, "    }}")?;
        writeln!(output, "}}")?;
        writeln!(output)?;
        Ok(())
    }

    fn write_builder_validate(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        writeln!(output, "impl {rust_typename}Builder {{")?;
        writeln!(output, "    #[allow(clippy::collapsible_if)]")?;
        writeln!(output, "    fn validate(&self) -> Result<(), String> {{")?;
        for (member_name, member) in &self.members {
            let rust_member_name = to_snake_case(member_name);
            let is_optional = member.is_optional();
            let is_list = member.is_list();

            if !is_optional && !is_list {
                writeln!(output, "        if self.{rust_member_name}.is_none() {{")?;
                writeln!(
                    output,
                    "            return Err(\"Missing required field '{member_name}' when building {rust_typename}\".to_string());"
                )?;
                writeln!(output, "        }}")?;
            }

            let member_validator = member.get_derive_builder_validator("value");
            if let Some(mut validator) = member_validator
                && !validator.trim().is_empty()
            {
                validator = validator.trim().replace("\n", "\n            ");
                if is_optional {
                    writeln!(
                        output,
                        "        if let Some(value_opt) = &self.{rust_member_name} && let Some(value) = value_opt {{"
                    )?;
                    writeln!(output, "            {validator}")?;
                    writeln!(output, "        }}")?;
                } else {
                    writeln!(output, "        if let Some(value) = &self.{rust_member_name} {{")?;
                    writeln!(output, "            {validator}")?;
                    writeln!(output, "        }}")?;
                }
            }
        }
        writeln!(output, "        Ok(())")?;
        writeln!(output, "    }}")?;
        writeln!(output, "}}")?;
        Ok(())
    }
}

impl Typed for Structure {
    fn rust_typename(&self) -> String {
        self.rust_typename.clone().expect("Structure type should be resolved before generating Rust code")
    }

    fn get_clap_parser(&self, optional: bool) -> String {
        let typename = self.rust_typename();
        if optional {
            format!("{typename}::parse_opt")
        } else {
            format!("{typename}::from_str")
        }
    }

    fn mark_reachable_from_input(&mut self) {
        if self.reachable_from_input {
            return;
        }

        self.reachable_from_input = true;

        self.members.values_mut().for_each(|member| {
            member.mark_reachable_from_input();
        });
    }

    fn write(&self, output: &mut dyn Write) -> IoResult<()> {
        self.write_rust_decl(output)?;
        self.write_rust_impl(output)?;
        if self.reachable_from_input {
            self.write_rust_from_str_impl(output)?;
            self.write_rust_try_from_shorthand_value_impl(output)?;
        }
        self.write_builder_validate(output)?;
        Ok(())
    }
}
