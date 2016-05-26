// A renderer for the input groups
var InputGroupBloc = React.createClass({

	/**
	 * Render function for InputGroupBloc
	 */
	render: function() {

		// If addon on right
		if (this.props.textOnLeft) return (
			<div class="input-group">
				<span class="input-group-addon">{this.props.addonText}</span>
				<input type="{this.props.inputType}" class="form-control" name="{this.props.inputName}" placeholder="{this.props.inputPlaceholder}" />
			</div>
		);

		// If addon on left
		else return (
			<div class="input-group">
				<input type="{this.props.inputType}" class="form-control" name="{this.props.inputName}" placeholder="{this.props.inputPlaceholder}" />
				<span class="input-group-addon">{this.props.addonText}</span>
			</div>
		);
	}
});


// The FormBloc renderer
var FormBloc = React.createClass({

	/**
	 * Getter of the initial state for parameters
	 */
	getInitialState: function() {
		return {
			baseUrl: 'http://127.0.0.1:2080',
			analyseAction: '/api/v1/testcase_analyse',
			dissectAction: '/api/v1/frames_dissect'
		};
	},

	/**
	 * Render function for FormBloc
	 */
	render: function() {
		return (
			<form action="{this.state.baseUrl + this.state.analyseAction}" method="post" enctype="multipart/form-data">
				<div class="col-sm-6">
					<div class="page-header">
						<h1>Pcap file to analyse</h1>
					</div>
					<InputGroupBloc inputName="pcap" inputType="file" addonText="Enter your pcap file" textOnLeft="True" inputPlaceholder="" />
				</div>

				<div class="col-sm-6">
					<div class="page-header">
						<h1>Analyse options</h1>
					</div>
					<InputGroupBloc inputName="frame-number" inputType="text" addonText="Enter your pcap file" textOnLeft="Frame number" inputPlaceholder="Enter a frame number if only one wanted" />

					<div style="{{textAlign: center}}">
						<div class="btn-group" data-toggle="buttons">
							<label class="btn btn-info active">
								<input type="radio" id="analyse-option" autocomplete="off" name="options" value="analyse" checked /> Analyse
							</label>
							<label class="btn btn-info">
								<input type="radio" id="dissect-option" autocomplete="off" name="options" value="dissect" /> Dissect
							</label>
						</div>
					</div>
				</div>

				<p style="{{textAlign: center}}">
					<input type="submit" value="Execute" class="btn btn-success centered-block" />
				</p>
			</form>
		);
	}
});


// The PcapForm renderer
var PcapForm = React.createClass({

	/**
	 * Render function for PcapForm
	 */
	render: function() {
		return (
			<div class="row">
				<FormBloc />
			</div>
		);
	}
});


ReactDOM.render(
	<PcapForm />,
	document.getElementById('content')
);