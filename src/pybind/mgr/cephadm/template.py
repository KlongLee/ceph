import copy
from typing import Optional, TYPE_CHECKING, Set

from jinja2 import Environment, PackageLoader, select_autoescape, StrictUndefined, meta
from jinja2 import exceptions as j2_exceptions

from ceph.deployment.service_spec import ServiceSpec

if TYPE_CHECKING:
    from cephadm.module import CephadmOrchestrator


class TemplateError(Exception):
    pass


class UndefinedError(TemplateError):
    pass


class TemplateNotFoundError(TemplateError):
    pass


class TemplateEngine:
    def render(self, name: str, context: Optional[dict] = None) -> str:
        raise NotImplementedError()


class Jinja2Engine(TemplateEngine):
    def __init__(self) -> None:
        self.env = Environment(
            loader=PackageLoader('cephadm', 'templates'),
            autoescape=select_autoescape(['html', 'xml'], default_for_string=False),
            trim_blocks=True,
            lstrip_blocks=True,
            undefined=StrictUndefined
        )

    def render(self, name: str, context: Optional[dict] = None) -> str:
        try:
            template = self.env.get_template(name)
            if context is None:
                return template.render()

            for u in self.find_undeclared_variables(name):
                if u != 'cephadm_managed' and u not in context:
                    context[u] = None

            return template.render(context)
        except j2_exceptions.UndefinedError as e:
            raise UndefinedError(e.message)
        except j2_exceptions.TemplateNotFound as e:
            raise TemplateNotFoundError(e.message)

    def render_plain(self, source: str, context: Optional[dict]) -> str:
        try:
            template = self.env.from_string(source)
            if context is None:
                return template.render()

            for u in self.find_undeclared_variables_plain(source, ''):
                if u != 'cephadm_managed' and u not in context:
                    context[u] = None

            return template.render(context)
        except j2_exceptions.UndefinedError as e:
            raise UndefinedError(e.message)
        except j2_exceptions.TemplateNotFound as e:
            raise TemplateNotFoundError(e.message)

    def find_undeclared_variables(self, name: str) -> Set[str]:
        assert self.env.loader
        contents, filename, _ = self.env.loader.get_source(self.env, name)
        parsed_content = self.env.parse(contents, filename, filename)
        return meta.find_undeclared_variables(parsed_content)

    def find_undeclared_variables_plain(self, source: str, name: str) -> Set[str]:
        assert self.env.loader
        parsed_content = self.env.parse(source, name)
        return meta.find_undeclared_variables(parsed_content)


class TemplateMgr:
    def __init__(self, mgr: "CephadmOrchestrator"):
        self.engine = Jinja2Engine()
        self.base_context = {
            'cephadm_managed': 'This file is generated by cephadm.'
        }
        self.mgr = mgr

    def render(self, name: str,
               context: Optional[dict] = None,
               managed_context: bool = True,
               host: Optional[str] = None) -> str:
        """Render a string from a template with context.

        :param name: template name. e.g. services/nfs/ganesha.conf.j2
        :type name: str
        :param context: a dictionary that contains values to be used in the template, defaults
            to None
        :type context: Optional[dict], optional
        :param managed_context: to inject default context like managed header or not, defaults
            to True
        :type managed_context: bool, optional
        :param host: The host name used to build the key to access
            the module's persistent key-value store.
        :type host: Optional[str], optional
        :return: the templated string
        :rtype: str
        """
        ctx = {}
        if managed_context:
            ctx = copy.deepcopy(self.base_context)
        if context is not None:
            ctx = {**ctx, **context}

        custom_template = self.get_custom_template(name, host)
        if custom_template:
            return self.engine.render_plain(custom_template, ctx)
        else:
            return self.engine.render(name, ctx)

    def find_undeclared_variables(self, name: str) -> Set[str]:
        custom_template = self.get_custom_template(name, '')
        if custom_template:
            undeclared = self.engine.find_undeclared_variables_plain(custom_template, name)
        else:
            undeclared = self.engine.find_undeclared_variables(name)
        if 'cephadm_managed' in undeclared:
            undeclared.remove('cephadm_managed')
        return undeclared

    def get_custom_template(self, name: str, host: Optional[str]) -> Optional[str]:
        # Check if the given name exists in the module's persistent
        # key-value store, e.g.
        # - blink_device_light_cmd
        # - <host>/blink_device_light_cmd
        # - services/nfs/ganesha.conf
        store_name = name.rstrip('.j2')
        custom_template = self.mgr.get_store(store_name, None)
        if host and custom_template is None:
            store_name = '{}/{}'.format(host, store_name)
            custom_template = self.mgr.get_store(store_name, None)
        return custom_template

    def mk_context(self, spec: ServiceSpec, ctx: dict) -> dict:
        ctx.update(spec.other_properties)
        return ctx
